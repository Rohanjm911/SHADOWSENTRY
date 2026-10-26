// Security Event data models
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventSeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventCategory {
    PortScan,
    ConnectionBurst,
    ConnectionFailure,
    DnsAnomaly,
    GatewayAnomaly,
    ArpAnomaly,
    ThreatIntelMatch,
    HoneypotInteraction,
    InboundAnomaly,
    ConfigChange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventStatus {
    Active,
    Investigating,
    Resolved,
    Dismissed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceField {
    pub label: String,
    pub value: serde_json::Value,
    pub highlight: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_id: String,
    pub timestamp: String,
    pub rule_id: String,
    pub rule_name: String,
    pub category: EventCategory,
    pub severity: EventSeverity,
    pub source_ip: Option<String>,
    pub source_port: Option<u16>,
    pub dest_ip: Option<String>,
    pub dest_port: Option<u16>,
    pub protocol: Option<String>,
    pub interface_name: Option<String>,
    
    // Explainability core
    pub what_observed: String,
    pub why_flagged: String,
    pub supporting_evidence: Vec<EvidenceField>,
    pub uncertainty_details: String,
    pub confidence_score: f64,
    pub recommended_steps: Vec<String>,
    
    pub status: EventStatus,
    pub user_notes: Option<String>,
    pub resolved_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EventFilterCriteria {
    pub severity: Option<Vec<EventSeverity>>,
    pub category: Option<Vec<EventCategory>>,
    pub status: Option<Vec<EventStatus>>,
    pub search_query: Option<String>,
    pub date_from: Option<String>,
    pub date_to: Option<String>,
    pub protocol: Option<String>,
    pub ip_address: Option<String>,
}
