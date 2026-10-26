export type EventSeverity = "critical" | "high" | "medium" | "low" | "informational";

export type EventCategory =
  | "port_scan"
  | "connection_burst"
  | "connection_failure"
  | "dns_anomaly"
  | "gateway_anomaly"
  | "arp_anomaly"
  | "threat_intel_match"
  | "honeypot_interaction"
  | "inbound_anomaly"
  | "config_change";

export type EventStatus = "active" | "investigating" | "resolved" | "dismissed";

export interface EvidenceField {
  label: string;
  value: string | number | boolean;
  highlight?: boolean;
}

export interface SecurityEvent {
  event_id: string;
  timestamp: string;
  rule_id: string;
  rule_name: string;
  category: EventCategory;
  severity: EventSeverity;
  source_ip: string | null;
  source_port: number | null;
  dest_ip: string | null;
  dest_port: number | null;
  protocol: string | null;
  interface_name: string | null;
  
  // Explainability Core
  what_observed: string;
  why_flagged: string;
  supporting_evidence: EvidenceField[];
  uncertainty_details: string;
  confidence_score: number; // 0.0 - 1.0
  recommended_steps: string[];
  
  status: EventStatus;
  user_notes?: string;
  resolved_at?: string;
}

export interface DetectionRuleConfig {
  rule_id: string;
  name: string;
  category: EventCategory;
  default_severity: EventSeverity;
  description: string;
  enabled: boolean;
  threshold_value: number;
  time_window_seconds: number;
  explanation_template: string;
}

export interface EventFilterCriteria {
  severity?: EventSeverity[];
  category?: EventCategory[];
  status?: EventStatus[];
  searchQuery?: string;
  dateFrom?: string;
  dateTo?: string;
  protocol?: string;
  ipAddress?: string;
}
