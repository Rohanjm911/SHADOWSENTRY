export interface PrivacySettings {
  retention_days: number;
  payload_capture_enabled: boolean;
  redact_sensitive_local_ips: boolean;
  telemetry_enabled: false; // strictly false
  bounded_log_size_mb: number;
}

export interface DetectionThresholds {
  port_scan_count: number;
  port_scan_window_secs: number;
  burst_packet_rate: number;
  burst_window_secs: number;
  failed_conn_count: number;
  failed_conn_window_secs: number;
  dns_entropy_min: number;
  dns_max_name_length: number;
  inbound_probe_threshold: number;
}

export interface AppSettings {
  theme: "dark" | "light";
  preferred_interface: string | null;
  preferred_backend: "npcap" | "raw_socket" | "iphelper" | "lab_synthetic";
  notifications_enabled: boolean;
  launch_at_startup: boolean;
  privacy: PrivacySettings;
  thresholds: DetectionThresholds;
}
