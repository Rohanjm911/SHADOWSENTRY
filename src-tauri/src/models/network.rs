// Network and interface data models
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureBackendType {
    Npcap,
    RawSocket,
    Iphelper,
    LabSynthetic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterfaceInfo {
    pub id: String,
    pub name: String,
    pub friendly_name: String,
    pub description: String,
    pub mac_address: String,
    pub ipv4_addresses: Vec<String>,
    pub ipv6_addresses: Vec<String>,
    pub gateway_ips: Vec<String>,
    pub is_up: bool,
    pub is_loopback: bool,
    pub is_wireless: bool,
    pub speed_mbps: u64,
    pub mtu: u32,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayInfo {
    pub ip_address: String,
    pub mac_address: String,
    pub interface_name: String,
    pub interface_index: u32,
    pub metric: u32,
    pub is_reachable: bool,
    pub last_observed: String,
    pub consecutive_changes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpEntry {
    pub ip_address: String,
    pub mac_address: String,
    pub interface_index: u32,
    pub entry_type: String, // "dynamic" | "static" | "invalid"
    pub state: String,
    pub last_updated: String,
    pub is_anomaly: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverStatus {
    pub npcap_installed: bool,
    pub npcap_version: Option<String>,
    pub npcap_service_running: bool,
    pub is_elevated_admin: bool,
    pub raw_sockets_supported: bool,
    pub supported_backends: Vec<CaptureBackendType>,
    pub recommended_backend: CaptureBackendType,
    pub diagnostic_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringStatus {
    pub is_active: bool,
    pub active_backend: Option<CaptureBackendType>,
    pub selected_interface: Option<String>,
    pub session_id: Option<String>,
    pub start_time: Option<String>,
    pub duration_seconds: u64,
    pub packet_count: u64,
    pub byte_count: u64,
    pub event_count: u64,
    pub is_paused: bool,
    pub metadata_only_mode: bool,
    pub error_message: Option<String>,
}
