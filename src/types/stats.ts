import { ProtocolType } from "./packet";
import { EventSeverity } from "./event";

export interface SessionStats {
  session_id: string;
  start_time: string;
  duration_seconds: number;
  total_packets: number;
  total_bytes: number;
  active_connections: number;
  security_findings_total: number;
  dns_queries_total: number;
  honeypot_probes_total: number;
  capture_backend: string;
  interface_name: string;
  packet_rate_per_sec: number;
  byte_rate_per_sec: number;
}

export interface ProtocolMetric {
  protocol: ProtocolType;
  packet_count: number;
  byte_count: number;
  percentage: number;
  color: string;
}

export interface TrafficTimelinePoint {
  timestamp: string;
  time_label: string;
  packet_count: number;
  byte_count: number;
  event_count: number;
}

export interface SeverityDistribution {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}

export interface NetworkHealthState {
  interface_up: boolean;
  gateway_reachable: boolean;
  gateway_ip: string | null;
  gateway_mac: string | null;
  dns_visibility: "visible" | "encrypted_partial" | "restricted";
  capture_driver_ready: boolean;
  honeypot_active: boolean;
  elevation_level: "administrator" | "standard_user";
}
