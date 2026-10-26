// Packet data models
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProtocolType {
    TCP,
    UDP,
    ICMP,
    DNS,
    ARP,
    #[serde(rename = "IPv6-ICMP")]
    IPv6Icmp,
    OTHER,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrafficDirection {
    Inbound,
    Outbound,
    Local,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSummary {
    pub query_id: u16,
    pub is_response: bool,
    pub query_name: String,
    pub query_type: String,
    pub response_code: Option<String>,
    pub resolved_ips: Vec<String>,
    pub latency_ms: Option<f64>,
    pub is_suspicious: bool,
    pub suspicious_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketMetadata {
    pub id: String,
    pub timestamp: String,
    pub interface_name: String,
    pub source_ip: String,
    pub source_port: Option<u16>,
    pub dest_ip: String,
    pub dest_port: Option<u16>,
    pub source_mac: Option<String>,
    pub dest_mac: Option<String>,
    pub protocol: ProtocolType,
    pub ip_version: Option<u8>,
    pub packet_size: usize,
    pub direction: TrafficDirection,
    pub tcp_flags: Option<TcpFlags>,
    pub dns_data: Option<DnsSummary>,
    pub has_security_event: bool,
    pub associated_event_id: Option<String>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQueryRecord {
    pub id: String,
    pub timestamp: String,
    pub query_name: String,
    pub record_type: String,
    pub client_ip: String,
    pub server_ip: String,
    pub response_code: Option<String>,
    pub resolved_ips: Vec<String>,
    pub latency_ms: Option<f64>,
    pub is_doh_or_encrypted: bool,
    pub entropy_score: f64,
    pub is_suspicious: bool,
    pub threat_flags: Vec<String>,
}
