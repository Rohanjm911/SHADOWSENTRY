// Integration and unit test suite for SHADOWSENTRY
// Tests packet parser, detection rules, database retention, and honeypot security.

use shadowsentry_lib::database::DatabaseManager;
use shadowsentry_lib::detection::DetectionEngine;
use shadowsentry_lib::models::{
    DetectionThresholds, EventCategory, EventSeverity, EventStatus, HoneypotInteractionLog,
    HoneypotServiceType, PacketMetadata, ProtocolType, TcpFlags, TrafficDirection,
};
use shadowsentry_lib::packet::{calculate_shannon_entropy, PacketParser};
use uuid::Uuid;

#[test]
fn test_packet_parser_malformed_input() {
    // Parser must handle truncated / corrupt frames without panicking
    let empty_slice: &[u8] = &[];
    assert!(PacketParser::parse_ethernet_frame(empty_slice, "test-iface").is_none());

    let short_slice = [0x00, 0x11, 0x22];
    assert!(PacketParser::parse_ethernet_frame(&short_slice, "test-iface").is_none());

    let garbage = vec![0xFF; 100];
    // Random garbage should not crash
    let _ = PacketParser::parse_ethernet_frame(&garbage, "test-iface");
    let _ = PacketParser::parse_raw_ip_packet(&garbage, "test-iface");
}

#[test]
fn test_shannon_entropy() {
    // Low entropy (repetitive)
    let low = calculate_shannon_entropy("aaaaaaaaaa");
    assert!(low < 0.1);

    // Medium entropy (standard English domain)
    let medium = calculate_shannon_entropy("google.com");
    assert!(medium > 1.5 && medium < 3.5);

    // High entropy (DGA randomized domain)
    let high = calculate_shannon_entropy("v9x7q8b3k1z0p5w4.top");
    assert!(high > 3.5);
}

#[test]
fn test_dns_parser_safe_handling() {
    // Minimal DNS query wire format: ID(2), Flags(2), QDCOUNT=1(2), ANCOUNT=0(2), NSCOUNT=0(2), ARCOUNT=0(2)
    // QNAME: 6 google 3 com 0, QTYPE: 1 (A), QCLASS: 1 (IN)
    let mut dns_wire = vec![
        0x12, 0x34, // ID
        0x01, 0x00, // Standard Query
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0
        // "google.com"
        0x06, b'g', b'o', b'o', b'g', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00,
        // QTYPE = A (1), QCLASS = IN (1)
        0x00, 0x01,
        0x00, 0x01,
    ];

    let summary = PacketParser::parse_dns_payload(&dns_wire).expect("DNS parse failed");
    assert_eq!(summary.query_id, 0x1234);
    assert_eq!(summary.query_name, "google.com");
    assert_eq!(summary.query_type, "A");
    assert!(!summary.is_response);

    // Corrupt DNS truncation test
    dns_wire.truncate(8);
    assert!(PacketParser::parse_dns_payload(&dns_wire).is_none());
}

#[test]
fn test_port_scan_detection_rule() {
    let thresholds = DetectionThresholds {
        port_scan_count: 5,
        port_scan_window_secs: 10,
        burst_packet_rate: 1000,
        burst_window_secs: 5,
        failed_conn_count: 20,
        failed_conn_window_secs: 10,
        dns_entropy_min: 3.8,
        dns_max_name_length: 55,
        inbound_probe_threshold: 10,
    };

    let engine = DetectionEngine::new(thresholds);
    let attacker = "192.168.1.99";

    let mut triggered_events = Vec::new();

    for port in 100..106 {
        let pkt = PacketMetadata {
            id: Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            interface_name: "test-eth".to_string(),
            source_ip: attacker.to_string(),
            source_port: Some(51234),
            dest_ip: "192.168.1.10".to_string(),
            dest_port: Some(port),
            source_mac: None,
            dest_mac: None,
            protocol: ProtocolType::TCP,
            ip_version: Some(4),
            packet_size: 60,
            direction: TrafficDirection::Inbound,
            tcp_flags: Some(TcpFlags {
                syn: true,
                ack: false,
                fin: false,
                rst: false,
                psh: false,
                urg: false,
            }),
            dns_data: None,
            has_security_event: false,
            associated_event_id: None,
            summary: "TCP SYN probe".to_string(),
        };

        let evts = engine.evaluate_packet(&pkt);
        triggered_events.extend(evts);
    }

    assert!(!triggered_events.is_empty(), "Port scan rule should trigger after 5 distinct ports");
    let event = &triggered_events[0];
    assert_eq!(event.category, EventCategory::PortScan);
    assert_eq!(event.severity, EventSeverity::High);
    assert!(event.what_observed.contains("192.168.1.99"));
}

#[test]
fn test_arp_anomaly_rule() {
    let thresholds = DetectionThresholds::default();
    let engine = DetectionEngine::new(thresholds);

    // Initial baseline observation
    let evt1 = engine.evaluate_arp_observation("192.168.1.1", "70:4F:57:A2:BB:01", true, "eth0");
    assert!(evt1.is_none(), "Initial observation establishes baseline, should not trigger");

    // Sudden change in MAC for same IP
    let evt2 = engine.evaluate_arp_observation("192.168.1.1", "00:11:22:33:44:99", true, "eth0");
    assert!(evt2.is_some(), "Conflicting MAC for gateway IP should trigger ARP anomaly");

    let event = evt2.unwrap();
    assert_eq!(event.category, EventCategory::ArpAnomaly);
    assert_eq!(event.severity, EventSeverity::Critical);
}

#[test]
fn test_honeypot_interaction_and_isolation() {
    let thresholds = DetectionThresholds::default();
    let engine = DetectionEngine::new(thresholds);

    let log = HoneypotInteractionLog {
        id: Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        service_type: HoneypotServiceType::HttpDecoy,
        client_ip: "192.168.1.200".to_string(),
        client_port: 48921,
        request_method: Some("GET".to_string()),
        path: Some("/.env".to_string()),
        probe_summary: "Recon probe targeting /.env".to_string(),
        user_agent: Some("curl/7.68.0".to_string()),
        payload_preview_sanitized: Some("GET /.env HTTP/1.1".to_string()),
        flagged_as_suspicious: true,
    };

    let evt = engine.evaluate_honeypot_interaction(&log);
    assert!(evt.is_some(), "Suspicious probe on decoy must trigger Honeypot Interaction event");
    let event = evt.unwrap();
    assert_eq!(event.category, EventCategory::HoneypotInteraction);
    assert_eq!(event.severity, EventSeverity::Critical);
}

#[test]
fn test_sqlite_in_memory_crud_and_retention() {
    let db = DatabaseManager::new_in_memory().expect("In-memory SQLite failed");

    let event = shadowsentry_lib::models::SecurityEvent {
        event_id: "test-event-01".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        rule_id: "RULE-01-PORT-SCAN".to_string(),
        rule_name: "Port Scan Test".to_string(),
        category: EventCategory::PortScan,
        severity: EventSeverity::High,
        source_ip: Some("10.0.0.5".to_string()),
        source_port: Some(5555),
        dest_ip: Some("10.0.0.1".to_string()),
        dest_port: Some(80),
        protocol: Some("TCP".to_string()),
        interface_name: Some("test0".to_string()),
        what_observed: "Port scan observed".to_string(),
        why_flagged: "Threshold met".to_string(),
        supporting_evidence: vec![],
        uncertainty_details: "None".to_string(),
        confidence_score: 0.9,
        recommended_steps: vec!["Step 1".to_string()],
        status: EventStatus::Active,
        user_notes: None,
        resolved_at: None,
    };

    // Insert
    db.insert_event(&event).expect("Insert event failed");

    // Query
    let events = db.get_events(None, 10).expect("Get events failed");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_id, "test-event-01");

    // Status update (investigating -> resolved without deletion)
    let updated = db.update_event_status("test-event-01", EventStatus::Resolved, Some("Confirmed scanner"))
        .expect("Update status failed");
    assert!(updated);

    let updated_events = db.get_events(None, 10).expect("Get events failed");
    assert_eq!(updated_events[0].status, EventStatus::Resolved);
    assert_eq!(updated_events[0].user_notes.as_deref(), Some("Confirmed scanner"));

    // User controlled purge
    let deleted = db.purge_database(None).expect("Purge failed");
    assert_eq!(deleted, 1);

    let empty_events = db.get_events(None, 10).expect("Get events failed");
    assert!(empty_events.is_empty());
}
