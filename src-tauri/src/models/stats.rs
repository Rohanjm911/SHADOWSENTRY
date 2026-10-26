// Statistics and telemetry models
use serde::{Deserialize, Serialize};
use super::packet::ProtocolType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStats {
    pub session_id: String,
    pub start_time: String,
    pub duration_seconds: u64,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub active_connections: usize,
    pub security_findings_total: usize,
    pub dns_queries_total: usize,
    pub honeypot_probes_total: usize,
    pub capture_backend: String,
    pub interface_name: String,
    pub packet_rate_per_sec: f64,
    pub byte_rate_per_sec: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMetric {
    pub protocol: ProtocolType,
    pub packet_count: u64,
    pub byte_count: u64,
    pub percentage: f64,
    pub color: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficTimelinePoint {
    pub timestamp: String,
    pub time_label: String,
    pub packet_count: u64,
    pub byte_count: u64,
    pub event_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityDistribution {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub informational: usize,
}
