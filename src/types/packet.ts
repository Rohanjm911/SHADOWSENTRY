export type ProtocolType = "TCP" | "UDP" | "ICMP" | "DNS" | "ARP" | "IPv6-ICMP" | "OTHER";
export type TrafficDirection = "inbound" | "outbound" | "local" | "unknown";

export interface TcpFlags {
  syn: boolean;
  ack: boolean;
  fin: boolean;
  rst: boolean;
  psh: boolean;
  urg: boolean;
}

export interface DnsSummary {
  query_id: number;
  is_response: boolean;
  query_name: string;
  query_type: string;
  response_code: string | null;
  resolved_ips: string[];
  latency_ms: number | null;
  is_suspicious: boolean;
  suspicious_reasons: string[];
}

export interface PacketMetadata {
  id: string;
  timestamp: string;
  interface_name: string;
  source_ip: string;
  source_port: number | null;
  dest_ip: string;
  dest_port: number | null;
  source_mac: string | null;
  dest_mac: string | null;
  protocol: ProtocolType;
  ip_version: 4 | 6 | null;
  packet_size: number;
  direction: TrafficDirection;
  tcp_flags: TcpFlags | null;
  dns_data: DnsSummary | null;
  has_security_event: boolean;
  associated_event_id: string | null;
  summary: string;
}

export interface DnsQueryRecord {
  id: string;
  timestamp: string;
  query_name: string;
  record_type: string;
  client_ip: string;
  server_ip: string;
  response_code: string | null;
  resolved_ips: string[];
  latency_ms: number | null;
  is_doh_or_encrypted: boolean;
  entropy_score: number;
  is_suspicious: boolean;
  threat_flags: string[];
}
