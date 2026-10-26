// Explainable Threat Detection Engine for SHADOWSENTRY
// Implements 10 modular detection rules with evidence, uncertainty, and actionable recommendations.

use crate::models::{
    DetectionThresholds, EvidenceField, EventCategory, EventSeverity, EventStatus,
    HoneypotInteractionLog, PacketMetadata, ProtocolType, SecurityEvent,
};
use chrono::Utc;
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use uuid::Uuid;

pub struct DetectionEngine {
    thresholds: Arc<Mutex<DetectionThresholds>>,
    // Rule 1: Port scan tracking (src_ip -> (set of target ports, first_seen_secs, last_seen_secs))
    port_scan_tracker: Mutex<HashMap<String, (HashSet<u16>, u64, u64)>>,
    // Rule 2: Burst tracker (timestamp_sec -> count)
    burst_tracker: Mutex<HashMap<u64, u64>>,
    // Rule 3: Connection failure tracker (src_ip -> (rst_count, timestamp_sec))
    failure_tracker: Mutex<HashMap<String, (u32, u64)>>,
    // Rule 5 & 6: Baseline tracking
    known_gateway_mac: Mutex<Option<String>>,
    known_arp_mappings: Mutex<HashMap<String, String>>, // IP -> MAC
    // Rule 7: Threat Intelligence indicator set (example known malicious IPs / subnets)
    threat_intel_ips: Mutex<HashSet<String>>,
    // Rule 8: Honeypot hit tracker (client_ip -> count)
    honeypot_hit_tracker: Mutex<HashMap<String, u32>>,
}

impl DetectionEngine {
    pub fn new(thresholds: DetectionThresholds) -> Self {
        let mut threat_ips = HashSet::new();
        // Standard sample threat intelligence indicators (RFC 5737 documentation test nets or known C2 simulator IPs)
        threat_ips.insert("198.51.100.42".to_string());
        threat_ips.insert("203.0.113.199".to_string());
        threat_ips.insert("185.220.101.5".to_string());
        threat_ips.insert("194.26.29.112".to_string());

        Self {
            thresholds: Arc::new(Mutex::new(thresholds)),
            port_scan_tracker: Mutex::new(HashMap::new()),
            burst_tracker: Mutex::new(HashMap::new()),
            failure_tracker: Mutex::new(HashMap::new()),
            known_gateway_mac: Mutex::new(None),
            known_arp_mappings: Mutex::new(HashMap::new()),
            threat_intel_ips: Mutex::new(threat_ips),
            honeypot_hit_tracker: Mutex::new(HashMap::new()),
        }
    }

    pub fn update_thresholds(&self, new_thresholds: DetectionThresholds) {
        *self.thresholds.lock() = new_thresholds;
    }

    /// Analyze incoming live packet metadata against active rules
    pub fn evaluate_packet(&self, packet: &PacketMetadata) -> Vec<SecurityEvent> {
        let mut events = Vec::new();
        let now_sec = Utc::now().timestamp() as u64;
        let thresholds = self.thresholds.lock().clone();

        // RULE 1: Multi-port Connection Sweep (Port Scan)
        if packet.protocol == ProtocolType::TCP {
            if let (Some(dp), Some(ref flags)) = (packet.dest_port, &packet.tcp_flags) {
                // Focus on SYN packets without ACK
                if flags.syn && !flags.ack {
                    let mut tracker = self.port_scan_tracker.lock();
                    let entry = tracker.entry(packet.source_ip.clone()).or_insert_with(|| (HashSet::new(), now_sec, now_sec));
                    
                    if now_sec - entry.1 > thresholds.port_scan_window_secs {
                        // Reset expired window
                        entry.0.clear();
                        entry.1 = now_sec;
                    }
                    entry.0.insert(dp);
                    entry.2 = now_sec;

                    if entry.0.len() >= thresholds.port_scan_count as usize {
                        let scanned_ports_count = entry.0.len();
                        events.push(SecurityEvent {
                            event_id: Uuid::new_v4().to_string(),
                            timestamp: Utc::now().to_rfc3339(),
                            rule_id: "RULE-01-PORT-SCAN".to_string(),
                            rule_name: "Repeated Connection Attempts Across Multiple Ports".to_string(),
                            category: EventCategory::PortScan,
                            severity: EventSeverity::High,
                            source_ip: Some(packet.source_ip.clone()),
                            source_port: packet.source_port,
                            dest_ip: Some(packet.dest_ip.clone()),
                            dest_port: Some(dp),
                            protocol: Some("TCP".to_string()),
                            interface_name: Some(packet.interface_name.clone()),
                            what_observed: format!(
                                "Source host {} initiated TCP SYN connection attempts targeting {} distinct destination ports within {} seconds.",
                                packet.source_ip, scanned_ports_count, thresholds.port_scan_window_secs
                            ),
                            why_flagged: "Consecutive connection attempts targeting multiple distinct TCP ports from a single origin is a characteristic signature of reconnaissance and port scanning.".to_string(),
                            supporting_evidence: vec![
                                EvidenceField { label: "Source IP".to_string(), value: serde_json::Value::String(packet.source_ip.clone()), highlight: Some(true) },
                                EvidenceField { label: "Target Ports Observed".to_string(), value: serde_json::Value::Number(scanned_ports_count.into()), highlight: Some(true) },
                                EvidenceField { label: "Time Window".to_string(), value: serde_json::Value::String(format!("{}s", thresholds.port_scan_window_secs)), highlight: None },
                                EvidenceField { label: "Current Destination Port".to_string(), value: serde_json::Value::Number(dp.into()), highlight: None },
                            ],
                            uncertainty_details: "May represent legitimate local service discovery, network inventory tools, or multi-port game/P2P clients.".to_string(),
                            confidence_score: 0.85,
                            recommended_steps: vec![
                                "Verify if the source IP belongs to an authorized asset inventory or vulnerability scanner.".to_string(),
                                "Inspect destination hosts to determine if services were listening on targeted ports.".to_string(),
                                "Review host firewall rules to restrict unauthenticated reconnaissance.".to_string(),
                            ],
                            status: EventStatus::Active,
                            user_notes: None,
                            resolved_at: None,
                        });
                        entry.0.clear(); // Reset after trigger to avoid flood
                    }
                }
            }
        }

        // RULE 2: Connection Burst Detection
        {
            let mut burst = self.burst_tracker.lock();
            let count = burst.entry(now_sec).or_insert(0);
            *count += 1;

            // Clean older timestamps
            burst.retain(|&ts, _| now_sec.saturating_sub(ts) <= thresholds.burst_window_secs);

            let total_in_window: u64 = burst.values().sum();
            if total_in_window >= thresholds.burst_packet_rate {
                events.push(SecurityEvent {
                    event_id: Uuid::new_v4().to_string(),
                    timestamp: Utc::now().to_rfc3339(),
                    rule_id: "RULE-02-BURST".to_string(),
                    rule_name: "Unusual Network Connection Burst".to_string(),
                    category: EventCategory::ConnectionBurst,
                    severity: EventSeverity::Medium,
                    source_ip: Some(packet.source_ip.clone()),
                    source_port: packet.source_port,
                    dest_ip: Some(packet.dest_ip.clone()),
                    dest_port: packet.dest_port,
                    protocol: Some(format!("{:?}", packet.protocol)),
                    interface_name: Some(packet.interface_name.clone()),
                    what_observed: format!(
                        "Sudden high traffic burst detected: {} packets observed within {} seconds on interface {}.",
                        total_in_window, thresholds.burst_window_secs, packet.interface_name
                    ),
                    why_flagged: "Traffic volume exceeded configured threshold rate, indicating potential flooding, large bulk transfers, or automated scan activity.".to_string(),
                    supporting_evidence: vec![
                        EvidenceField { label: "Observed Packet Count".to_string(), value: serde_json::Value::Number(total_in_window.into()), highlight: Some(true) },
                        EvidenceField { label: "Burst Window".to_string(), value: serde_json::Value::String(format!("{}s", thresholds.burst_window_secs)), highlight: None },
                        EvidenceField { label: "Threshold Rate".to_string(), value: serde_json::Value::Number(thresholds.burst_packet_rate.into()), highlight: None },
                    ],
                    uncertainty_details: "Could be legitimate heavy video streaming, large file synchronization, software updates, or speed testing.".to_string(),
                    confidence_score: 0.70,
                    recommended_steps: vec![
                        "Identify the application generating elevated throughput in Windows Task Manager or Resource Monitor.".to_string(),
                        "Check if network throughput returns to baseline within standard operating tolerances.".to_string(),
                    ],
                    status: EventStatus::Active,
                    user_notes: None,
                    resolved_at: None,
                });
                burst.clear();
            }
        }

        // RULE 3: Repeated Connection Failures (TCP RST / Rejected Attempts)
        if packet.protocol == ProtocolType::TCP {
            if let Some(ref flags) = packet.tcp_flags {
                if flags.rst {
                    let mut tracker = self.failure_tracker.lock();
                    let entry = tracker.entry(packet.source_ip.clone()).or_insert((0, now_sec));
                    if now_sec - entry.1 > thresholds.failed_conn_window_secs {
                        *entry = (0, now_sec);
                    }
                    entry.0 += 1;

                    if entry.0 >= thresholds.failed_conn_count {
                        events.push(SecurityEvent {
                            event_id: Uuid::new_v4().to_string(),
                            timestamp: Utc::now().to_rfc3339(),
                            rule_id: "RULE-03-CONN-FAILURES".to_string(),
                            rule_name: "Repeated Connection Failures (RST Surge)".to_string(),
                            category: EventCategory::ConnectionFailure,
                            severity: EventSeverity::Medium,
                            source_ip: Some(packet.source_ip.clone()),
                            source_port: packet.source_port,
                            dest_ip: Some(packet.dest_ip.clone()),
                            dest_port: packet.dest_port,
                            protocol: Some("TCP".to_string()),
                            interface_name: Some(packet.interface_name.clone()),
                            what_observed: format!(
                                "Observed {} TCP connection terminations or resets involving host {} within {} seconds.",
                                entry.0, packet.source_ip, thresholds.failed_conn_window_secs
                            ),
                            why_flagged: "A high volume of TCP RST packets frequently indicates connections being refused by closed ports or terminated by firewall filters.".to_string(),
                            supporting_evidence: vec![
                                EvidenceField { label: "Failed/RST Count".to_string(), value: serde_json::Value::Number(entry.0.into()), highlight: Some(true) },
                                EvidenceField { label: "Source Host".to_string(), value: serde_json::Value::String(packet.source_ip.clone()), highlight: None },
                            ],
                            uncertainty_details: "Can occur when a local server process crashes, during firewall timeouts, or when remote servers forcibly close idle sessions.".to_string(),
                            confidence_score: 0.65,
                            recommended_steps: vec![
                                "Verify if local services expected on target ports are running.".to_string(),
                                "Inspect firewall drop logs to check for blocked connection attempts.".to_string(),
                            ],
                            status: EventStatus::Active,
                            user_notes: None,
                            resolved_at: None,
                        });
                        entry.0 = 0;
                    }
                }
            }
        }

        // RULE 4: Suspicious DNS Patterns
        if let Some(ref dns) = packet.dns_data {
            if dns.is_suspicious {
                events.push(SecurityEvent {
                    event_id: Uuid::new_v4().to_string(),
                    timestamp: Utc::now().to_rfc3339(),
                    rule_id: "RULE-04-SUSP-DNS".to_string(),
                    rule_name: "Suspicious DNS Query Indicator".to_string(),
                    category: EventCategory::DnsAnomaly,
                    severity: EventSeverity::High,
                    source_ip: Some(packet.source_ip.clone()),
                    source_port: packet.source_port,
                    dest_ip: Some(packet.dest_ip.clone()),
                    dest_port: packet.dest_port,
                    protocol: Some("DNS".to_string()),
                    interface_name: Some(packet.interface_name.clone()),
                    what_observed: format!(
                        "DNS query observed for '{}' exhibiting unusual heuristics: {}.",
                        dns.query_name, dns.suspicious_reasons.join(", ")
                    ),
                    why_flagged: "High Shannon entropy or abnormal domain lengths are algorithmic signatures frequently correlated with Domain Generation Algorithms (DGA) or DNS tunneling.".to_string(),
                    supporting_evidence: vec![
                        EvidenceField { label: "Domain Name".to_string(), value: serde_json::Value::String(dns.query_name.clone()), highlight: Some(true) },
                        EvidenceField { label: "Query Type".to_string(), value: serde_json::Value::String(dns.query_type.clone()), highlight: None },
                        EvidenceField { label: "Indicators".to_string(), value: serde_json::Value::String(dns.suspicious_reasons.join("; ")), highlight: Some(true) },
                    ],
                    uncertainty_details: "Content delivery networks (CDNs), anti-virus telemetry, and modern load balancers occasionally employ randomized hostnames.".to_string(),
                    confidence_score: 0.78,
                    recommended_steps: vec![
                        "Investigate the local process that issued the DNS query using Netstat or Process Explorer.".to_string(),
                        "Check domain reputation in threat intelligence repositories (e.g. VirusTotal, AlienVault OTX).".to_string(),
                        "Check whether queries to this domain recur at regular automated intervals.".to_string(),
                    ],
                    status: EventStatus::Active,
                    user_notes: None,
                    resolved_at: None,
                });
            }
        }

        // RULE 7: Threat Intelligence Indicator Match
        {
            let intel = self.threat_intel_ips.lock();
            let is_match = intel.contains(&packet.source_ip) || intel.contains(&packet.dest_ip);
            if is_match {
                let matched_ip = if intel.contains(&packet.source_ip) { packet.source_ip.clone() } else { packet.dest_ip.clone() };
                events.push(SecurityEvent {
                    event_id: Uuid::new_v4().to_string(),
                    timestamp: Utc::now().to_rfc3339(),
                    rule_id: "RULE-07-THREAT-INTEL".to_string(),
                    rule_name: "Connection Matching Threat Intelligence Indicator".to_string(),
                    category: EventCategory::ThreatIntelMatch,
                    severity: EventSeverity::Critical,
                    source_ip: Some(packet.source_ip.clone()),
                    source_port: packet.source_port,
                    dest_ip: Some(packet.dest_ip.clone()),
                    dest_port: packet.dest_port,
                    protocol: Some(format!("{:?}", packet.protocol)),
                    interface_name: Some(packet.interface_name.clone()),
                    what_observed: format!(
                        "Connection established with IP address {} which matches configured threat intelligence blacklist.",
                        matched_ip
                    ),
                    why_flagged: "The destination or source IP matches a known malicious command-and-control server, active exploit scanner, or botnet node.".to_string(),
                    supporting_evidence: vec![
                        EvidenceField { label: "Matched IP Indicator".to_string(), value: serde_json::Value::String(matched_ip), highlight: Some(true) },
                        EvidenceField { label: "Protocol".to_string(), value: serde_json::Value::String(format!("{:?}", packet.protocol)), highlight: None },
                    ],
                    uncertainty_details: "Threat intelligence indicators can become stale if IP addresses are reallocated by cloud hosting providers.".to_string(),
                    confidence_score: 0.92,
                    recommended_steps: vec![
                        "Isolate the host or terminate the active socket connection immediately.".to_string(),
                        "Inspect memory and disk persistence mechanisms on the initiating process.".to_string(),
                        "Review DNS resolution history to identify initial access vector.".to_string(),
                    ],
                    status: EventStatus::Active,
                    user_notes: None,
                    resolved_at: None,
                });
            }
        }

        // RULE 9: Unusual Inbound Connection Pattern
        if packet.direction == crate::models::TrafficDirection::Inbound && packet.protocol == ProtocolType::TCP {
            if let (Some(dp), Some(ref flags)) = (packet.dest_port, &packet.tcp_flags) {
                if flags.syn && !flags.ack {
                    // Check for unusual ports (e.g. database, remote management, SMB on non-server workstation)
                    let sensitive_ports = [445, 135, 139, 3389, 5985, 5986, 1433, 3306, 5432, 23, 21];
                    if sensitive_ports.contains(&dp) {
                        events.push(SecurityEvent {
                            event_id: Uuid::new_v4().to_string(),
                            timestamp: Utc::now().to_rfc3339(),
                            rule_id: "RULE-09-INBOUND-ANOMALY".to_string(),
                            rule_name: "Unusual Inbound Connection Attempt to Sensitive Port".to_string(),
                            category: EventCategory::InboundAnomaly,
                            severity: EventSeverity::High,
                            source_ip: Some(packet.source_ip.clone()),
                            source_port: packet.source_port,
                            dest_ip: Some(packet.dest_ip.clone()),
                            dest_port: Some(dp),
                            protocol: Some("TCP".to_string()),
                            interface_name: Some(packet.interface_name.clone()),
                            what_observed: format!(
                                "Inbound TCP connection attempt from {} targeting administrative port {} on this workstation.",
                                packet.source_ip, dp
                            ),
                            why_flagged: "Unsolicited inbound requests to internal administrative or database ports typically represent lateral movement attempts or automated worms.".to_string(),
                            supporting_evidence: vec![
                                EvidenceField { label: "Source IP".to_string(), value: serde_json::Value::String(packet.source_ip.clone()), highlight: Some(true) },
                                EvidenceField { label: "Target Port".to_string(), value: serde_json::Value::Number(dp.into()), highlight: Some(true) },
                            ],
                            uncertainty_details: "Legitimate administrator remote desktop, domain controller RPC queries, or scheduled management scripts can target these ports.".to_string(),
                            confidence_score: 0.80,
                            recommended_steps: vec![
                                "Confirm whether remote administration from this source IP is authorized.".to_string(),
                                "Ensure Windows Defender Firewall blocks unsolicited incoming traffic on public and private profiles.".to_string(),
                            ],
                            status: EventStatus::Active,
                            user_notes: None,
                            resolved_at: None,
                        });
                    }
                }
            }
        }

        events
    }

    /// Evaluate ARP anomaly (Rule 6)
    pub fn evaluate_arp_observation(
        &self,
        ip: &str,
        mac: &str,
        is_reply: bool,
        interface_name: &str,
    ) -> Option<SecurityEvent> {
        let mut mappings = self.known_arp_mappings.lock();
        if let Some(prev_mac) = mappings.get(ip) {
            if prev_mac != mac {
                let prev_mac_clone = prev_mac.clone();
                mappings.insert(ip.to_string(), mac.to_string());

                return Some(SecurityEvent {
                    event_id: Uuid::new_v4().to_string(),
                    timestamp: Utc::now().to_rfc3339(),
                    rule_id: "RULE-06-ARP-ANOMALY".to_string(),
                    rule_name: "ARP Address-Mapping Anomaly Detected".to_string(),
                    category: EventCategory::ArpAnomaly,
                    severity: EventSeverity::Critical,
                    source_ip: Some(ip.to_string()),
                    source_port: None,
                    dest_ip: None,
                    dest_port: None,
                    protocol: Some("ARP".to_string()),
                    interface_name: Some(interface_name.to_string()),
                    what_observed: format!(
                        "IP address {} changed its hardware MAC address mapping from {} to {}.",
                        ip, prev_mac_clone, mac
                    ),
                    why_flagged: "Sudden reassignment of an IP address to a different MAC address on a local segment is a primary indicator of ARP spoofing / poisoning (Man-in-the-Middle) attack.".to_string(),
                    supporting_evidence: vec![
                        EvidenceField { label: "IP Address".to_string(), value: serde_json::Value::String(ip.to_string()), highlight: Some(true) },
                        EvidenceField { label: "Previous MAC".to_string(), value: serde_json::Value::String(prev_mac_clone), highlight: None },
                        EvidenceField { label: "New MAC".to_string(), value: serde_json::Value::String(mac.to_string()), highlight: Some(true) },
                        EvidenceField { label: "Packet Type".to_string(), value: serde_json::Value::String(if is_reply { "ARP Reply".to_string() } else { "ARP Request".to_string() }), highlight: None },
                    ],
                    uncertainty_details: "Can legitimately occur when a router/switch is swapped, when roaming between Wi-Fi access points, or during DHCP address reassignment.".to_string(),
                    confidence_score: 0.88,
                    recommended_steps: vec![
                        "Verify physical router or gateway hardware replacement with network administrators.".to_string(),
                        "Check ARP table with 'arp -a' in Windows terminal.".to_string(),
                        "Enable Dynamic ARP Inspection (DAI) on managed network switches if supported.".to_string(),
                    ],
                    status: EventStatus::Active,
                    user_notes: None,
                    resolved_at: None,
                });
            }
        } else {
            mappings.insert(ip.to_string(), mac.to_string());
        }
        None
    }

    /// Evaluate Gateway Identity Change (Rule 5)
    pub fn evaluate_gateway_change(&self, gateway_ip: &str, gateway_mac: &str, interface_name: &str) -> Option<SecurityEvent> {
        let mut current_mac = self.known_gateway_mac.lock();
        if let Some(ref prev_mac) = *current_mac {
            if prev_mac != gateway_mac {
                let prev_mac_clone = prev_mac.clone();
                *current_mac = Some(gateway_mac.to_string());

                return Some(SecurityEvent {
                    event_id: Uuid::new_v4().to_string(),
                    timestamp: Utc::now().to_rfc3339(),
                    rule_id: "RULE-05-GATEWAY-CHANGE".to_string(),
                    rule_name: "Default Gateway Identity Change".to_string(),
                    category: EventCategory::GatewayAnomaly,
                    severity: EventSeverity::High,
                    source_ip: Some(gateway_ip.to_string()),
                    source_port: None,
                    dest_ip: None,
                    dest_port: None,
                    protocol: Some("IP-Routing".to_string()),
                    interface_name: Some(interface_name.to_string()),
                    what_observed: format!(
                        "The default gateway at {} changed hardware identity from {} to {}.",
                        gateway_ip, prev_mac_clone, gateway_mac
                    ),
                    why_flagged: "A change in default gateway hardware identity may indicate unauthorized rogue router deployment, ARP redirection, or network re-routing.".to_string(),
                    supporting_evidence: vec![
                        EvidenceField { label: "Gateway IP".to_string(), value: serde_json::Value::String(gateway_ip.to_string()), highlight: None },
                        EvidenceField { label: "Prior Gateway MAC".to_string(), value: serde_json::Value::String(prev_mac_clone), highlight: None },
                        EvidenceField { label: "Current Gateway MAC".to_string(), value: serde_json::Value::String(gateway_mac.to_string()), highlight: Some(true) },
                    ],
                    uncertainty_details: "Occurs legitimately during Wi-Fi roaming, VPN connection establishment/disconnection, or DHCP lease renewal on changing networks.".to_string(),
                    confidence_score: 0.82,
                    recommended_steps: vec![
                        "Check if the host recently reconnected to a different Wi-Fi network or VPN tunnel.".to_string(),
                        "Inspect default route table via 'route print' in Windows PowerShell.".to_string(),
                    ],
                    status: EventStatus::Active,
                    user_notes: None,
                    resolved_at: None,
                });
            }
        } else {
            *current_mac = Some(gateway_mac.to_string());
        }
        None
    }

    /// Evaluate Honeypot Interaction (Rule 8)
    pub fn evaluate_honeypot_interaction(&self, log: &HoneypotInteractionLog) -> Option<SecurityEvent> {
        let mut hit_tracker = self.honeypot_hit_tracker.lock();
        let count = hit_tracker.entry(log.client_ip.clone()).or_insert(0);
        *count += 1;

        if *count >= 2 || log.flagged_as_suspicious {
            let hit_count = *count;
            return Some(SecurityEvent {
                event_id: Uuid::new_v4().to_string(),
                timestamp: Utc::now().to_rfc3339(),
                rule_id: "RULE-08-HONEYPOT-INTERACTION".to_string(),
                rule_name: "Repeated Honeypot Decoy Service Interaction".to_string(),
                category: EventCategory::HoneypotInteraction,
                severity: EventSeverity::Critical,
                source_ip: Some(log.client_ip.clone()),
                source_port: Some(log.client_port),
                dest_ip: Some("127.0.0.1".to_string()),
                dest_port: None,
                protocol: Some(format!("{:?}", log.service_type)),
                interface_name: Some("Local Decoy".to_string()),
                what_observed: format!(
                    "Client IP {} interacted with honeypot decoy service {} ({}) {} times. Recent probe: {}",
                    log.client_ip, format!("{:?}", log.service_type), log.path.as_deref().unwrap_or(""), hit_count, log.probe_summary
                ),
                why_flagged: "Honeypot services have no legitimate operational purpose in regular workflows. Any traffic directed toward them indicates active reconnaissance, automated credential spraying, or malware probing.".to_string(),
                supporting_evidence: vec![
                    EvidenceField { label: "Client IP".to_string(), value: serde_json::Value::String(log.client_ip.clone()), highlight: Some(true) },
                    EvidenceField { label: "Interaction Count".to_string(), value: serde_json::Value::Number(hit_count.into()), highlight: Some(true) },
                    EvidenceField { label: "Service".to_string(), value: serde_json::Value::String(format!("{:?}", log.service_type)), highlight: None },
                    EvidenceField { label: "Probe Summary".to_string(), value: serde_json::Value::String(log.probe_summary.clone()), highlight: None },
                ],
                uncertainty_details: "If bound to loopback, this may be user self-testing or local security assessment software.".to_string(),
                confidence_score: 0.98,
                recommended_steps: vec![
                    "Identify the local or network process originating connections to honeypot ports.".to_string(),
                    "Check if the interaction was part of authorized security lab testing.".to_string(),
                    "Block the offending source IP at network or host firewall boundaries.".to_string(),
                ],
                status: EventStatus::Active,
                user_notes: None,
                resolved_at: None,
            });
        }
        None
    }

    /// Evaluate Monitoring Configuration Change (Rule 10)
    pub fn evaluate_config_change(&self, event_description: &str, details: &str) -> SecurityEvent {
        SecurityEvent {
            event_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            rule_id: "RULE-10-CONFIG-CHANGE".to_string(),
            rule_name: "Unexpected Monitoring State or Configuration Change".to_string(),
            category: EventCategory::ConfigChange,
            severity: EventSeverity::Medium,
            source_ip: None,
            source_port: None,
            dest_ip: None,
            dest_port: None,
            protocol: None,
            interface_name: None,
            what_observed: event_description.to_string(),
            why_flagged: "A change in monitoring interface availability or packet capture state affects network visibility.".to_string(),
            supporting_evidence: vec![
                EvidenceField { label: "Details".to_string(), value: serde_json::Value::String(details.to_string()), highlight: None },
            ],
            uncertainty_details: "Can be initiated by manual user actions, interface power-saving states, or VPN connect/disconnect events.".to_string(),
            confidence_score: 0.90,
            recommended_steps: vec![
                "Verify whether the network monitoring change was user-initiated.".to_string(),
                "Confirm network adapter link status in Windows Network Connections.".to_string(),
            ],
            status: EventStatus::Active,
            user_notes: None,
            resolved_at: None,
        }
    }
}
