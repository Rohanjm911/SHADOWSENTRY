export type HoneypotServiceType = "http_decoy" | "admin_portal" | "ssh_banner";

export interface HoneypotServiceState {
  service_type: HoneypotServiceType;
  name: string;
  description: string;
  is_running: boolean;
  bind_address: string;
  port: number;
  allow_lan: boolean;
  max_connections_per_minute: number;
  total_connections_seen: number;
  last_interaction_time: string | null;
  status_message: string;
}

export interface HoneypotInteractionLog {
  id: string;
  timestamp: string;
  service_type: HoneypotServiceType;
  client_ip: string;
  client_port: number;
  request_method: string | null;
  path: string | null;
  probe_summary: string;
  user_agent: string | null;
  payload_preview_sanitized: string | null;
  flagged_as_suspicious: boolean;
}

export interface HoneypotSimulationResult {
  success: boolean;
  service_type: string;
  target_address: string;
  request_preview: string;
  response_preview: string;
  latency_ms: number;
  event_created: boolean;
  message: string;
}
