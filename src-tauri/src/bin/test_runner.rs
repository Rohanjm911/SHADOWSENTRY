// Automated Security Test Suite & Verification Runner for SHADOWSENTRY
// Tests packet parser, 10 explainable detection rules, honeypot safety, and SQLite storage.

use shadowsentry_lib::database::DatabaseManager;
use shadowsentry_lib::detection::DetectionEngine;
use shadowsentry_lib::models::{
    DetectionThresholds, EventCategory, EventSeverity, EventStatus, HoneypotInteractionLog,
    HoneypotServiceType, PacketMetadata, ProtocolType, TcpFlags, TrafficDirection,
};
use shadowsentry_lib::packet::{calculate_shannon_entropy, PacketParser};
use uuid::Uuid;

fn main() {
    println!("============================================================");
    println!("SHADOWSENTRY — Automated Test Suite & Engine Verification");
    println!("Invisible Threats. Visible Intelligence.");
    println!("============================================================\n");

    let mut passed = 0;
    let mut failed = 0;

    macro_rules! run_test {
        ($name:expr, $func:expr) => {
            print!("TEST: {:<50} ... ", $name);
            match std::panic::catch_unwind(|| $func()) {
                Ok(_) => {
                    println!("[PASS]");
                    passed += 1;
                }
                Err(e) => {
                    println!("[FAIL]");
                    eprintln!("  Error: {:?}", e);
                    failed += 1;
                }
            }
        };
    }

    // 1. Packet Parser Tests
    run_test!("Malformed / Truncated Frame Handling", || {
        let empty: &[u8] = &[];
        assert!(PacketParser::parse_ethernet_frame(empty, "eth0").is_none());

        let short = [0x00, 0x11, 0x22];
        assert!(PacketParser::parse_ethernet_frame(&short, "eth0").is_none());

        let garbage = vec![0xEE; 150];
        let _ = PacketParser::parse_ethernet_frame(&garbage, "eth0");
        let _ = PacketParser::parse_raw_ip_packet(&garbage, "eth0");
    });

    run_test!("Shannon Entropy Algorithm (DGA Detection)", || {
        let low = calculate_shannon_entropy("aaaaaaaaaa");
        assert!(low < 0.1, "Repetitive string should have near-zero entropy");

        let normal = calculate_shannon_entropy("microsoft.com");
        assert!(normal > 1.5 && normal < 3.5, "Standard domain entropy expected");

        let dga = calculate_shannon_entropy("v9x7q8b3k1z0p5w4.top");
        assert!(dga > 3.6, "DGA domain should exceed entropy threshold 3.6");
    });

    run_test!("DNS Wire Format Parser & Question Decoding", || {
        let dns_wire = vec![
            0x12, 0x34, // Query ID 0x1234
            0x01, 0x00, // Standard Query
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, 0x00, 0x00,
            // QNAME: "google.com"
            0x06, b'g', b'o', b'o', b'g', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
        ];

        let summary = PacketParser::parse_dns_payload(&dns_wire).expect("DNS parse failed");
        assert_eq!(summary.query_id, 0x1234);
        assert_eq!(summary.query_name, "google.com");
        assert_eq!(summary.query_type, "A");
        assert!(!summary.is_response);
    });

    // 2. Detection Rule Tests
    run_test!("Rule 1: Multi-port Connection Sweep (Port Scan)", || {
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
        let mut triggered = Vec::new();

        for port in 100..106 {
            let pkt = PacketMetadata {
                id: Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                interface_name: "eth0".to_string(),
                source_ip: "192.168.1.188".to_string(),
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
            triggered.extend(engine.evaluate_packet(&pkt));
        }

        assert!(!triggered.is_empty(), "Port scan rule should trigger after 5 distinct ports");
        assert_eq!(triggered[0].category, EventCategory::PortScan);
        assert_eq!(triggered[0].severity, EventSeverity::High);
    });

    run_test!("Rule 4: Suspicious DNS DGA Pattern Heuristics", || {
        let thresholds = DetectionThresholds::default();
        let engine = DetectionEngine::new(thresholds);

        let pkt = PacketMetadata {
            id: Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            interface_name: "eth0".to_string(),
            source_ip: "192.168.1.10".to_string(),
            source_port: Some(52100),
            dest_ip: "8.8.8.8".to_string(),
            dest_port: Some(53),
            source_mac: None,
            dest_mac: None,
            protocol: ProtocolType::DNS,
            ip_version: Some(4),
            packet_size: 98,
            direction: TrafficDirection::Outbound,
            tcp_flags: None,
            dns_data: Some(shadowsentry_lib::models::DnsSummary {
                query_id: 1111,
                is_response: false,
                query_name: "a998bc49281df881023ba118741.malware-dga.top".to_string(),
                query_type: "A".to_string(),
                response_code: None,
                resolved_ips: vec![],
                latency_ms: None,
                is_suspicious: true,
                suspicious_reasons: vec!["High entropy string".to_string()],
            }),
            has_security_event: false,
            associated_event_id: None,
            summary: "DNS Query".to_string(),
        };

        let evts = engine.evaluate_packet(&pkt);
        assert!(!evts.is_empty(), "Rule 4 should trigger on suspicious DNS query");
        assert_eq!(evts[0].category, EventCategory::DnsAnomaly);
    });

    run_test!("Rule 5 & 6: Gateway & ARP Address-Mapping Anomaly", || {
        let thresholds = DetectionThresholds::default();
        let engine = DetectionEngine::new(thresholds);

        // Baseline
        assert!(engine.evaluate_arp_observation("192.168.1.1", "70:4F:57:A2:BB:01", true, "eth0").is_none());

        // Conflicting MAC change for same IP
        let arp_evt = engine.evaluate_arp_observation("192.168.1.1", "00:11:22:33:44:99", true, "eth0");
        assert!(arp_evt.is_some(), "Conflicting MAC for gateway IP should trigger ARP anomaly");
        assert_eq!(arp_evt.unwrap().category, EventCategory::ArpAnomaly);

        // Gateway identity change
        assert!(engine.evaluate_gateway_change("192.168.1.1", "70:4F:57:A2:BB:01", "eth0").is_none());
        let gw_evt = engine.evaluate_gateway_change("192.168.1.1", "AA:BB:CC:DD:EE:FF", "eth0");
        assert!(gw_evt.is_some(), "Gateway MAC change should trigger Gateway anomaly");
        assert_eq!(gw_evt.unwrap().category, EventCategory::GatewayAnomaly);
    });

    run_test!("Rule 7: Threat Intelligence Indicator Match", || {
        let thresholds = DetectionThresholds::default();
        let engine = DetectionEngine::new(thresholds);

        let pkt = PacketMetadata {
            id: Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            interface_name: "eth0".to_string(),
            source_ip: "192.168.1.10".to_string(),
            source_port: Some(51200),
            dest_ip: "185.220.101.5".to_string(), // Known indicator
            dest_port: Some(443),
            source_mac: None,
            dest_mac: None,
            protocol: ProtocolType::TCP,
            ip_version: Some(4),
            packet_size: 1420,
            direction: TrafficDirection::Outbound,
            tcp_flags: None,
            dns_data: None,
            has_security_event: false,
            associated_event_id: None,
            summary: "Outbound to known indicator".to_string(),
        };

        let evts = engine.evaluate_packet(&pkt);
        assert!(!evts.is_empty(), "Connection to threat intel IP must trigger Rule 7");
        assert_eq!(evts[0].category, EventCategory::ThreatIntelMatch);
        assert_eq!(evts[0].severity, EventSeverity::Critical);
    });

    run_test!("Rule 8: Honeypot Decoy Interaction Heuristic", || {
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
        assert!(evt.is_some(), "Honeypot probe must trigger Honeypot Interaction event");
        assert_eq!(evt.unwrap().category, EventCategory::HoneypotInteraction);
    });

    run_test!("Rule 2: Unusual Connection Burst (Traffic Flood)", || {
        let thresholds = DetectionThresholds {
            burst_packet_rate: 5,
            burst_window_secs: 5,
            ..DetectionThresholds::default()
        };
        let engine = DetectionEngine::new(thresholds);
        let mut triggered = Vec::new();

        for _ in 0..6 {
            let pkt = PacketMetadata {
                id: Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                interface_name: "eth0".to_string(),
                source_ip: "10.0.0.50".to_string(),
                source_port: Some(4000),
                dest_ip: "10.0.0.1".to_string(),
                dest_port: Some(80),
                source_mac: None,
                dest_mac: None,
                protocol: ProtocolType::TCP,
                ip_version: Some(4),
                packet_size: 1500,
                direction: TrafficDirection::Inbound,
                tcp_flags: None,
                dns_data: None,
                has_security_event: false,
                associated_event_id: None,
                summary: "Bulk traffic".to_string(),
            };
            triggered.extend(engine.evaluate_packet(&pkt));
        }

        assert!(!triggered.is_empty(), "Traffic burst exceeding threshold must trigger Rule 2");
        assert_eq!(triggered[0].category, EventCategory::ConnectionBurst);
        assert_eq!(triggered[0].severity, EventSeverity::Medium);
    });

    run_test!("Rule 3: Repeated Connection Failures (RST Surge)", || {
        let thresholds = DetectionThresholds {
            failed_conn_count: 3,
            failed_conn_window_secs: 10,
            ..DetectionThresholds::default()
        };
        let engine = DetectionEngine::new(thresholds);
        let mut triggered = Vec::new();

        for _ in 0..4 {
            let pkt = PacketMetadata {
                id: Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                interface_name: "eth0".to_string(),
                source_ip: "192.168.1.55".to_string(),
                source_port: Some(443),
                dest_ip: "192.168.1.10".to_string(),
                dest_port: Some(51234),
                source_mac: None,
                dest_mac: None,
                protocol: ProtocolType::TCP,
                ip_version: Some(4),
                packet_size: 54,
                direction: TrafficDirection::Inbound,
                tcp_flags: Some(TcpFlags {
                    syn: false,
                    ack: false,
                    fin: false,
                    rst: true,
                    psh: false,
                    urg: false,
                }),
                dns_data: None,
                has_security_event: false,
                associated_event_id: None,
                summary: "TCP RST rejection".to_string(),
            };
            triggered.extend(engine.evaluate_packet(&pkt));
        }

        assert!(!triggered.is_empty(), "Repeated RST packets must trigger Rule 3");
        assert_eq!(triggered[0].category, EventCategory::ConnectionFailure);
    });

    run_test!("Rule 9: Unusual Inbound Connection to Sensitive Port", || {
        let thresholds = DetectionThresholds::default();
        let engine = DetectionEngine::new(thresholds);

        let pkt = PacketMetadata {
            id: Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            interface_name: "eth0".to_string(),
            source_ip: "10.10.10.200".to_string(),
            source_port: Some(48920),
            dest_ip: "192.168.1.10".to_string(),
            dest_port: Some(445), // SMB / RPC
            source_mac: None,
            dest_mac: None,
            protocol: ProtocolType::TCP,
            ip_version: Some(4),
            packet_size: 64,
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
            summary: "Inbound SMB connection attempt".to_string(),
        };

        let evts = engine.evaluate_packet(&pkt);
        assert!(!evts.is_empty(), "Inbound SYN to SMB port 445 must trigger Rule 9");
        assert_eq!(evts[0].category, EventCategory::InboundAnomaly);
        assert_eq!(evts[0].severity, EventSeverity::High);
    });

    run_test!("Rule 10: Unexpected Monitoring Configuration Change", || {
        let thresholds = DetectionThresholds::default();
        let engine = DetectionEngine::new(thresholds);

        let evt = engine.evaluate_config_change(
            "Primary network interface 'Ethernet 1' disconnected.",
            "Adapter link status transitioned from Up to Down during active monitoring session.",
        );

        assert_eq!(evt.category, EventCategory::ConfigChange);
        assert_eq!(evt.severity, EventSeverity::Medium);
        assert!(evt.what_observed.contains("disconnected"));
    });

    // 3. SQLite Database Layer Tests
    run_test!("SQLite In-Memory Schema, CRUD & Status Retention", || {
        let db = DatabaseManager::new_in_memory().expect("In-memory SQLite failed");

        let event = shadowsentry_lib::models::SecurityEvent {
            event_id: "test-001".to_string(),
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
            interface_name: Some("eth0".to_string()),
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
        let evts = db.get_events(None, 10).expect("Get events failed");
        assert_eq!(evts.len(), 1);
        assert_eq!(evts[0].event_id, "test-001");

        // Status update (investigating -> resolved without deletion)
        assert!(db.update_event_status("test-001", EventStatus::Resolved, Some("Investigated")).unwrap());
        let updated = db.get_events(None, 10).unwrap();
        assert_eq!(updated[0].status, EventStatus::Resolved);
        assert_eq!(updated[0].user_notes.as_deref(), Some("Investigated"));

        // User controlled purge
        let deleted = db.purge_database(None).unwrap();
        assert_eq!(deleted, 1);
        assert!(db.get_events(None, 10).unwrap().is_empty());
    });

    // 4. Test Fixtures & Scenario Verification
    run_test!("Test Fixture Catalog Verification (10 Rules & Scenarios)", || {
        let fixture_paths = [
            "../tests/detection-cases/case_01_port_scan.json",
            "../tests/detection-cases/case_02_connection_burst.json",
            "../tests/detection-cases/case_03_connection_failures.json",
            "../tests/detection-cases/case_04_dga_dns.json",
            "../tests/detection-cases/case_05_gateway_change.json",
            "../tests/detection-cases/case_06_arp_anomaly.json",
            "../tests/detection-cases/case_07_threat_intel.json",
            "../tests/detection-cases/case_08_honeypot_interaction.json",
            "../tests/detection-cases/case_09_inbound_anomaly.json",
            "../tests/detection-cases/case_10_config_change.json",
            "../tests/honeypot-scenarios/scenario_http_decoy.json",
            "../tests/honeypot-scenarios/scenario_admin_panel.json",
            "../tests/honeypot-scenarios/scenario_ssh_banner.json",
            "../tests/packet-fixtures/tcp_syn_probe.json",
            "../tests/packet-fixtures/dns_query_wire.json",
            "../tests/packet-fixtures/arp_conflict_frame.json",
            "../tests/packet-fixtures/malformed_ip_frame.json",
        ];

        for path in &fixture_paths {
            let data = std::fs::read_to_string(path)
                .or_else(|_| std::fs::read_to_string(path.trim_start_matches("../")))
                .or_else(|_| std::fs::read_to_string(format!("../{}", path)))
                .unwrap_or_else(|_| panic!("Failed to read fixture file: {}", path));
            let parsed: serde_json::Value = serde_json::from_str(&data)
                .unwrap_or_else(|_| panic!("Fixture file is invalid JSON: {}", path));
            assert!(parsed.is_object(), "Fixture must be a JSON object: {}", path);
        }
    });

    println!("\n============================================================");
    println!("TEST RESULTS: {} passed, {} failed", passed, failed);
    println!("============================================================");

    if failed > 0 {
        std::process::exit(1);
    }
}
