// Application settings and privacy models
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacySettings {
    pub retention_days: u32,
    pub payload_capture_enabled: bool,
    pub redact_sensitive_local_ips: bool,
    pub telemetry_enabled: bool, // Always false
    pub bounded_log_size_mb: u32,
}

impl Default for PrivacySettings {
    fn default() -> Self {
        Self {
            retention_days: 14,
            payload_capture_enabled: false,
            redact_sensitive_local_ips: false,
            telemetry_enabled: false,
            bounded_log_size_mb: 250,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionThresholds {
    pub port_scan_count: u32,
    pub port_scan_window_secs: u64,
    pub burst_packet_rate: u64,
    pub burst_window_secs: u64,
    pub failed_conn_count: u32,
    pub failed_conn_window_secs: u64,
    pub dns_entropy_min: f64,
    pub dns_max_name_length: usize,
    pub inbound_probe_threshold: u32,
}

impl Default for DetectionThresholds {
    fn default() -> Self {
        Self {
            port_scan_count: 15,
            port_scan_window_secs: 10,
            burst_packet_rate: 1000,
            burst_window_secs: 5,
            failed_conn_count: 20,
            failed_conn_window_secs: 10,
            dns_entropy_min: 3.8,
            dns_max_name_length: 55,
            inbound_probe_threshold: 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub theme: String,
    pub preferred_interface: Option<String>,
    pub preferred_backend: String,
    pub notifications_enabled: bool,
    pub launch_at_startup: bool,
    pub privacy: PrivacySettings,
    pub thresholds: DetectionThresholds,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            theme: "dark".to_string(),
            preferred_interface: None,
            preferred_backend: "raw_socket".to_string(),
            notifications_enabled: true,
            launch_at_startup: false,
            privacy: PrivacySettings::default(),
            thresholds: DetectionThresholds::default(),
        }
    }
}
