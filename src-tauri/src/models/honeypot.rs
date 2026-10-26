// Honeypot laboratory data models
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoneypotServiceType {
    HttpDecoy,
    AdminPortal,
    SshBanner,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotServiceState {
    pub service_type: HoneypotServiceType,
    pub name: String,
    pub description: String,
    pub is_running: bool,
    pub bind_address: String,
    pub port: u16,
    pub allow_lan: bool,
    pub max_connections_per_minute: u32,
    pub total_connections_seen: u64,
    pub last_interaction_time: Option<String>,
    pub status_message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotInteractionLog {
    pub id: String,
    pub timestamp: String,
    pub service_type: HoneypotServiceType,
    pub client_ip: String,
    pub client_port: u16,
    pub request_method: Option<String>,
    pub path: Option<String>,
    pub probe_summary: String,
    pub user_agent: Option<String>,
    pub payload_preview_sanitized: Option<String>,
    pub flagged_as_suspicious: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotSimulationResult {
    pub success: bool,
    pub service_type: String,
    pub target_address: String,
    pub request_preview: String,
    pub response_preview: String,
    pub latency_ms: u64,
    pub event_created: bool,
    pub message: String,
}
