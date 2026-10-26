export type CaptureBackendType = "npcap" | "raw_socket" | "iphelper" | "lab_synthetic";

export interface NetworkInterfaceInfo {
  id: string;
  name: string;
  friendly_name: string;
  description: string;
  mac_address: string;
  ipv4_addresses: string[];
  ipv6_addresses: string[];
  gateway_ips: string[];
  is_up: boolean;
  is_loopback: boolean;
  is_wireless: boolean;
  speed_mbps: number;
  mtu: number;
}

export interface GatewayInfo {
  ip_address: string;
  mac_address: string;
  interface_name: string;
  interface_index: number;
  metric: number;
  is_reachable: boolean;
  last_observed: string;
  consecutive_changes: number;
}

export interface ArpEntry {
  ip_address: string;
  mac_address: string;
  interface_index: number;
  entry_type: "dynamic" | "static" | "invalid";
  state: string;
  last_updated: string;
  is_anomaly?: boolean;
}

export interface DriverStatus {
  npcap_installed: boolean;
  npcap_version: string | null;
  npcap_service_running: boolean;
  is_elevated_admin: boolean;
  raw_sockets_supported: boolean;
  supported_backends: CaptureBackendType[];
  recommended_backend: CaptureBackendType;
  diagnostic_notes: string[];
}

export interface MonitoringStatus {
  is_active: boolean;
  active_backend: CaptureBackendType | null;
  selected_interface: string | null;
  session_id: string | null;
  start_time: string | null;
  duration_seconds: number;
  packet_count: number;
  byte_count: number;
  event_count: number;
  is_paused: boolean;
  metadata_only_mode: boolean;
  error_message: string | null;
}
