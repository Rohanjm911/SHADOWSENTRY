import React, { useState, useMemo } from "react";
import { SecurityEvent, EventStatus } from "../../types/event";
import { ThreatSeverityBadge } from "../../components/ThreatSeverityBadge";
import { formatDateTime } from "../../lib/formatters";
import { soundEffects } from "../../lib/soundEffects";
import { TableEmptyRow } from "../../components/EmptyState";
import {
  Search,
  CheckCircle2,
  AlertTriangle,
  Info,
  Shield,
  Copy,
  Download,
  Check,
  Flame,
  Radio,
  Target,
  ArrowRight,
} from "lucide-react";

interface ThreatCenterPageProps {
  events: SecurityEvent[];
  onSelectEvent: (event: SecurityEvent) => void;
  selectedEventId?: string | null;
  onUpdateStatus?: (eventId: string, newStatus: EventStatus) => Promise<void>;
}

interface MitreMapping {
  phase: "RECONNAISSANCE" | "LATERAL MOVEMENT" | "COMMAND & CONTROL" | "INITIAL ACCESS" | "DEFENSE EVASION" | "DENIAL OF SERVICE";
  techniqueId: string;
  techniqueName: string;
  color: string;
}

const MITRE_RULES_MAP: Record<string, MitreMapping> = {
  "RULE-01-PORT-SCAN": {
    phase: "RECONNAISSANCE",
    techniqueId: "T1046",
    techniqueName: "Network Service Discovery",
    color: "#38BDF8",
  },
  "RULE-02-BURST": {
    phase: "DENIAL OF SERVICE",
    techniqueId: "T1498",
    techniqueName: "Network Denial of Service",
    color: "#FB923C",
  },
  "RULE-03-CONN-FAILURES": {
    phase: "RECONNAISSANCE",
    techniqueId: "T1046",
    techniqueName: "Port Knocking / Scanning",
    color: "#FBBF24",
  },
  "RULE-04-SUSP-DNS": {
    phase: "COMMAND & CONTROL",
    techniqueId: "T1071.004",
    techniqueName: "DNS C2 & Data Exfiltration",
    color: "#A78BFA",
  },
  "RULE-05-GATEWAY-CHANGE": {
    phase: "INITIAL ACCESS",
    techniqueId: "T1557",
    techniqueName: "Adversary-in-the-Middle (Gateway Hijack)",
    color: "#F43F5E",
  },
  "RULE-06-ARP-ANOMALY": {
    phase: "LATERAL MOVEMENT",
    techniqueId: "T1557.002",
    techniqueName: "ARP Cache Poisoning",
    color: "#EF4444",
  },
  "RULE-07-THREAT-INTEL": {
    phase: "COMMAND & CONTROL",
    techniqueId: "T1071",
    techniqueName: "Known Malicious C2 Infrastructure",
    color: "#EC4899",
  },
  "RULE-08-HONEYPOT-INTERACTION": {
    phase: "RECONNAISSANCE",
    techniqueId: "T1018",
    techniqueName: "Decoy Service Intrusion Probe",
    color: "#2DD4BF",
  },
  "RULE-09-INBOUND-ANOMALY": {
    phase: "LATERAL MOVEMENT",
    techniqueId: "T1021",
    techniqueName: "Remote Admin Protocol Probe",
    color: "#FB7185",
  },
  "RULE-10-CONFIG-CHANGE": {
    phase: "DEFENSE EVASION",
    techniqueId: "T1562",
    techniqueName: "Impair Defenses / Sniffer Tamper",
    color: "#FBBF24",
  },
};

const KILL_CHAIN_PHASES = [
  { id: "ALL", label: "All Phases" },
  { id: "RECONNAISSANCE", label: "Reconnaissance", color: "#38BDF8" },
  { id: "INITIAL ACCESS", label: "Initial Access", color: "#F43F5E" },
  { id: "LATERAL MOVEMENT", label: "Lateral Movement", color: "#EF4444" },
  { id: "COMMAND & CONTROL", label: "Command & Control", color: "#A78BFA" },
  { id: "DENIAL OF SERVICE", label: "Denial of Service", color: "#FB923C" },
  { id: "DEFENSE EVASION", label: "Defense Evasion", color: "#FBBF24" },
];

export const ThreatCenterPage: React.FC<ThreatCenterPageProps> = ({
  events,
  onSelectEvent,
  selectedEventId,
  onUpdateStatus,
}) => {
  const [selectedSeverity, setSelectedSeverity] = useState<string>("ALL");
  const [selectedStatus, setSelectedStatus] = useState<string>("active");
  const [selectedPhase, setSelectedPhase] = useState<string>("ALL");
  const [searchTerm, setSearchTerm] = useState<string>("");
  const [triageToast, setTriageToast] = useState<string | null>(null);

  const selectedEvent = useMemo(() => {
    return events.find((e) => e.event_id === selectedEventId) || null;
  }, [events, selectedEventId]);

  const severityCounts = useMemo(() => {
    return {
      all: events.length,
      critical: events.filter((e) => e.severity === "critical").length,
      high: events.filter((e) => e.severity === "high").length,
      medium: events.filter((e) => e.severity === "medium").length,
      low: events.filter((e) => e.severity === "low").length,
      informational: events.filter((e) => e.severity === "informational").length,
    };
  }, [events]);

  const phaseCounts = useMemo(() => {
    const counts: Record<string, number> = { ALL: events.length };
    KILL_CHAIN_PHASES.forEach((p) => {
      if (p.id !== "ALL") counts[p.id] = 0;
    });

    events.forEach((e) => {
      const mapping = MITRE_RULES_MAP[e.rule_id];
      if (mapping && counts[mapping.phase] !== undefined) {
        counts[mapping.phase]++;
      }
    });
    return counts;
  }, [events]);

  const filteredEvents = useMemo(() => {
    return events.filter((e) => {
      if (selectedSeverity !== "ALL" && e.severity !== selectedSeverity) {
        return false;
      }
      if (selectedStatus !== "ALL" && e.status !== selectedStatus) {
        return false;
      }
      if (selectedPhase !== "ALL") {
        const mapping = MITRE_RULES_MAP[e.rule_id];
        if (!mapping || mapping.phase !== selectedPhase) {
          return false;
        }
      }
      if (searchTerm.trim() !== "") {
        const q = searchTerm.toLowerCase();
        const mapping = MITRE_RULES_MAP[e.rule_id];
        const matches =
          e.rule_name.toLowerCase().includes(q) ||
          e.what_observed.toLowerCase().includes(q) ||
          e.why_flagged.toLowerCase().includes(q) ||
          (mapping && mapping.techniqueId.toLowerCase().includes(q)) ||
          (e.source_ip && e.source_ip.toLowerCase().includes(q)) ||
          (e.dest_ip && e.dest_ip.toLowerCase().includes(q));
        if (!matches) return false;
      }
      return true;
    });
  }, [events, selectedSeverity, selectedStatus, selectedPhase, searchTerm]);

  const handleCopyFirewallRule = (ip: string) => {
    const ruleCmd = `netsh advfirewall firewall add rule name="ShadowSentry-Block-${ip}" dir=in action=block remoteip=${ip}`;
    navigator.clipboard.writeText(ruleCmd);
    soundEffects.playToggle();
    setTriageToast(`Windows Firewall Block Rule copied for ${ip}!`);
    setTimeout(() => setTriageToast(null), 3000);
  };

  const handleExportIncidentJson = (event: SecurityEvent) => {
    const mapping = MITRE_RULES_MAP[event.rule_id];
    const report = {
      incident_id: event.event_id,
      timestamp: event.timestamp,
      rule_id: event.rule_id,
      rule_name: event.rule_name,
      severity: event.severity,
      status: event.status,
      confidence: event.confidence_score,
      mitre_attack: mapping
        ? {
            phase: mapping.phase,
            technique_id: mapping.techniqueId,
            technique_name: mapping.techniqueName,
          }
        : null,
      source: {
        ip: event.source_ip,
        port: event.source_port,
      },
      target: {
        ip: event.dest_ip,
        port: event.dest_port,
      },
      forensics: {
        what_observed: event.what_observed,
        why_flagged: event.why_flagged,
        recommendations: event.recommended_steps,
        uncertainty: event.uncertainty_details,
      },
      supporting_evidence: event.supporting_evidence,
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `incident-${event.event_id.slice(0, 8)}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    soundEffects.playToggle();
  };

  return (
    <div
      style={{
        flex: 1,
        display: "flex",
        flexDirection: "column",
        padding: "16px 20px",
        gap: "12px",
        overflow: "hidden",
        height: "100%",
      }}
    >
      {/* Top Banner: Heuristics & Explainability Philosophy */}
      <div
        style={{
          padding: "9px 14px",
          backgroundColor: "var(--color-surface)",
          border: "1px solid var(--color-border)",
          borderRadius: "var(--radius-sm)",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          fontSize: "12px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <Info size={15} style={{ color: "var(--color-accent-primary)" }} />
          <span>
            <strong style={{ color: "var(--color-text-primary)" }}>Explainable Threat Analysis:</strong> Findings reflect transparent heuristic rules mapped to the MITRE ATT&CK framework.
          </span>
        </div>
        <span style={{ color: "var(--color-text-muted)", fontSize: "11px" }}>
          10 Deterministic Analyzers
        </span>
      </div>

      {/* MITRE ATT&CK Kill-Chain Phase Ribbon */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "6px",
          overflowX: "auto",
          paddingBottom: "2px",
        }}
      >
        <div style={{ fontSize: "10.5px", fontWeight: 700, color: "var(--color-text-muted)", textTransform: "uppercase", marginRight: "4px" }}>
          Kill-Chain:
        </div>
        {KILL_CHAIN_PHASES.map((phase) => {
          const isSelected = selectedPhase === phase.id;
          const count = phaseCounts[phase.id] || 0;
          return (
            <button
              key={phase.id}
              onClick={() => setSelectedPhase(phase.id)}
              style={{
                fontSize: "11px",
                padding: "4px 8px",
                borderRadius: "var(--radius-sm)",
                backgroundColor: isSelected ? "var(--color-surface-elevated)" : "var(--color-surface)",
                border: `1px solid ${isSelected ? phase.color || "var(--color-accent-primary)" : "var(--color-border)"}`,
                color: isSelected ? "var(--color-text-primary)" : "var(--color-text-secondary)",
                display: "flex",
                alignItems: "center",
                gap: "5px",
                fontWeight: isSelected ? 600 : 400,
                whiteSpace: "nowrap",
                transition: "all 0.15s ease",
              }}
            >
              <span>{phase.label}</span>
              <span
                style={{
                  fontSize: "9.5px",
                  fontWeight: 700,
                  padding: "1px 5px",
                  borderRadius: "10px",
                  backgroundColor: isSelected ? (phase.color || "var(--color-accent-primary)") : "var(--color-border)",
                  color: isSelected ? "#000000" : "var(--color-text-muted)",
                }}
              >
                {count}
              </span>
            </button>
          );
        })}
      </div>

      {/* 1-Click Incident Triage Action Bar (Visible when an incident is selected) */}
      {selectedEvent && (
        <div
          className="animate-slide-in"
          style={{
            padding: "10px 14px",
            backgroundColor: "var(--color-surface-elevated)",
            border: "1px solid var(--color-accent-primary)",
            borderRadius: "var(--radius-sm)",
            boxShadow: "0 4px 16px rgba(0, 0, 0, 0.25)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: "12px",
            flexWrap: "wrap",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <div
              style={{
                width: "28px",
                height: "28px",
                borderRadius: "var(--radius-sm)",
                backgroundColor: "rgba(56, 189, 248, 0.15)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "var(--color-accent-primary)",
              }}
            >
              <Target size={16} />
            </div>
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                <span style={{ fontSize: "12px", fontWeight: 700, color: "var(--color-text-primary)" }}>
                  {selectedEvent.rule_name}
                </span>
                {MITRE_RULES_MAP[selectedEvent.rule_id] && (
                  <span
                    style={{
                      fontSize: "9px",
                      fontWeight: 700,
                      padding: "1px 5px",
                      borderRadius: "3px",
                      backgroundColor: "rgba(167, 139, 250, 0.15)",
                      color: "#A78BFA",
                      border: "1px solid #A78BFA",
                    }}
                  >
                    {MITRE_RULES_MAP[selectedEvent.rule_id].techniqueId}
                  </span>
                )}
              </div>
              <div style={{ fontSize: "10.5px", color: "var(--color-text-muted)" }}>
                Origin: <span className="font-mono" style={{ color: "var(--color-text-secondary)" }}>{selectedEvent.source_ip || "Unknown"}</span> &rarr; Target: <span className="font-mono" style={{ color: "var(--color-text-secondary)" }}>{selectedEvent.dest_ip || "Local Host"}</span>
              </div>
            </div>
          </div>

          {/* Quick Triage Buttons */}
          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            {selectedEvent.source_ip && selectedEvent.source_ip !== "127.0.0.1" && (
              <button
                className="ghost"
                onClick={() => handleCopyFirewallRule(selectedEvent.source_ip!)}
                title="Copy Windows Firewall block rule"
                style={{ fontSize: "11px", padding: "4px 8px", color: "var(--color-critical)", borderColor: "var(--color-critical)" }}
              >
                <Shield size={12} />
                <span>Isolate Host IP</span>
              </button>
            )}

            <button
              className="ghost"
              onClick={() => handleExportIncidentJson(selectedEvent)}
              title="Export Incident Forensics as JSON"
              style={{ fontSize: "11px", padding: "4px 8px" }}
            >
              <Download size={12} />
              <span>Export JSON</span>
            </button>

            {onUpdateStatus && selectedEvent.status === "active" && (
              <button
                className="ghost"
                onClick={() => onUpdateStatus(selectedEvent.event_id, "investigating")}
                style={{ fontSize: "11px", padding: "4px 8px", color: "var(--color-warning)" }}
              >
                <span>Investigate</span>
              </button>
            )}

            {onUpdateStatus && selectedEvent.status !== "resolved" && (
              <button
                className="primary"
                onClick={() => onUpdateStatus(selectedEvent.event_id, "resolved")}
                style={{ fontSize: "11px", padding: "4px 8px" }}
              >
                <Check size={12} />
                <span>Resolve</span>
              </button>
            )}
          </div>
        </div>
      )}

      {/* Toast Feedback */}
      {triageToast && (
        <div
          className="animate-fade-in"
          style={{
            padding: "6px 12px",
            backgroundColor: "rgba(52, 211, 153, 0.15)",
            border: "1px solid var(--color-success)",
            color: "var(--color-success)",
            borderRadius: "var(--radius-sm)",
            fontSize: "11.5px",
            display: "flex",
            alignItems: "center",
            gap: "6px",
          }}
        >
          <CheckCircle2 size={13} />
          <span>{triageToast}</span>
        </div>
      )}

      {/* Severity Filter Cards Row */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: "8px" }}>
        {[
          { id: "critical", label: "Critical", count: severityCounts.critical, color: "var(--color-critical)", bg: "#2A1215" },
          { id: "high", label: "High", count: severityCounts.high, color: "var(--color-high)", bg: "#2A1810" },
          { id: "medium", label: "Medium", count: severityCounts.medium, color: "var(--color-warning)", bg: "#28200F" },
          { id: "low", label: "Low", count: severityCounts.low, color: "var(--color-low)", bg: "#10232A" },
          { id: "informational", label: "Informational", count: severityCounts.informational, color: "var(--color-info)", bg: "#131E2E" },
        ].map((item) => {
          const isSelected = selectedSeverity === item.id;
          return (
            <div
              key={item.id}
              onClick={() => setSelectedSeverity(isSelected ? "ALL" : item.id)}
              style={{
                backgroundColor: isSelected ? item.bg : "var(--color-surface)",
                border: `1px solid ${isSelected ? item.color : "var(--color-border)"}`,
                borderRadius: "var(--radius-sm)",
                padding: "8px 12px",
                cursor: "pointer",
                transition: "all 0.15s ease",
              }}
            >
              <div style={{ fontSize: "10.5px", color: "var(--color-text-muted)", textTransform: "uppercase", fontWeight: 600 }}>
                {item.label}
              </div>
              <div style={{ fontSize: "18px", fontWeight: 700, color: item.color, fontFamily: "var(--font-mono)", marginTop: "1px" }}>
                {item.count}
              </div>
            </div>
          );
        })}
      </div>

      {/* Status Bar and Search */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "10px", flexWrap: "wrap" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "5px" }}>
          <span style={{ fontSize: "11px", color: "var(--color-text-muted)", marginRight: "3px" }}>Status:</span>
          {[
            { id: "ALL", label: "All" },
            { id: "active", label: "Active" },
            { id: "investigating", label: "Investigating" },
            { id: "resolved", label: "Resolved" },
            { id: "dismissed", label: "Dismissed" },
          ].map((st) => {
            const active = selectedStatus === st.id;
            return (
              <button
                key={st.id}
                onClick={() => setSelectedStatus(st.id)}
                style={{
                  fontSize: "11px",
                  padding: "3px 7px",
                  backgroundColor: active ? "var(--color-surface-elevated)" : "var(--color-surface)",
                  borderColor: active ? "var(--color-accent-primary)" : "var(--color-border)",
                  color: active ? "var(--color-text-primary)" : "var(--color-text-secondary)",
                  fontWeight: active ? 600 : 400,
                }}
              >
                {st.label}
              </button>
            );
          })}
        </div>

        <div style={{ position: "relative" }}>
          <Search
            size={13}
            style={{
              position: "absolute",
              left: "8px",
              top: "50%",
              transform: "translateY(-50%)",
              color: "var(--color-text-muted)",
            }}
          />
          <input
            type="text"
            placeholder="Filter by rule, MITRE ID, IP..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              paddingLeft: "26px",
              fontSize: "11.5px",
              height: "27px",
              width: "220px",
            }}
          />
        </div>
      </div>

      {/* Events Table */}
      <div
        className="table-wrapper"
        tabIndex={0}
        role="region"
        aria-label="Security events table"
        style={{ flex: 1, minHeight: 0 }}
      >
        <table>
          <thead>
            <tr>
              <th style={{ width: "95px" }}>Severity</th>
              <th style={{ width: "115px" }}>Rule ID</th>
              <th style={{ width: "105px" }}>MITRE ATT&CK</th>
              <th>Incident Details</th>
              <th>Origin Host</th>
              <th>Target Address</th>
              <th style={{ width: "75px" }}>Score</th>
              <th style={{ width: "85px" }}>Status</th>
              <th style={{ width: "135px" }}>Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {filteredEvents.length === 0 ? (
              <TableEmptyRow
                colSpan={9}
                title={searchTerm.trim() !== "" || selectedSeverity !== "ALL" || selectedStatus !== "ALL" || selectedPhase !== "ALL"
                  ? "No Security Alerts Match Criteria"
                  : "All Systems Clear — Zero Threats Observed"}
                description={searchTerm.trim() !== "" || selectedSeverity !== "ALL" || selectedStatus !== "ALL" || selectedPhase !== "ALL"
                  ? "No security findings match the active filter or search criteria."
                  : "Continuous heuristics report zero suspicious network traffic or port sweeps."}
                badgeText="10 Heuristic Rules Active • SQLite Threat Guard"
                iconType={searchTerm.trim() !== "" || selectedSeverity !== "ALL" || selectedStatus !== "ALL" || selectedPhase !== "ALL" ? "search" : "success"}
              />
            ) : (
              filteredEvents.map((e) => {
                const isSelected = selectedEventId === e.event_id;
                const mitre = MITRE_RULES_MAP[e.rule_id];
                return (
                  <tr
                    key={e.event_id}
                    onClick={() => onSelectEvent(e)}
                    className={isSelected ? "selected" : ""}
                    style={{ cursor: "pointer" }}
                  >
                    <td>
                      <ThreatSeverityBadge severity={e.severity} />
                    </td>
                    <td className="font-mono" style={{ fontSize: "11px", color: "var(--color-text-secondary)" }}>
                      {e.rule_id}
                    </td>
                    <td>
                      {mitre ? (
                        <span
                          style={{
                            fontSize: "10px",
                            fontWeight: 700,
                            padding: "2px 5px",
                            borderRadius: "3px",
                            backgroundColor: "rgba(167, 139, 250, 0.12)",
                            color: mitre.color || "#A78BFA",
                            border: `1px solid ${mitre.color || "#A78BFA"}`,
                            whiteSpace: "nowrap",
                          }}
                        >
                          {mitre.techniqueId}
                        </span>
                      ) : (
                        <span style={{ color: "var(--color-text-muted)", fontSize: "10px" }}>—</span>
                      )}
                    </td>
                    <td style={{ fontWeight: 600, color: "var(--color-text-primary)", maxWidth: "260px", overflow: "hidden", textOverflow: "ellipsis" }}>
                      {e.rule_name}
                    </td>
                    <td className="font-mono" style={{ fontSize: "11px" }}>
                      {e.source_ip ? `${e.source_ip}${e.source_port ? `:${e.source_port}` : ""}` : "—"}
                    </td>
                    <td className="font-mono" style={{ fontSize: "11px" }}>
                      {e.dest_ip ? `${e.dest_ip}${e.dest_port ? `:${e.dest_port}` : ""}` : "—"}
                    </td>
                    <td className="font-mono" style={{ fontSize: "11px" }}>
                      {Math.round(e.confidence_score * 100)}%
                    </td>
                    <td>
                      <span
                        className="badge"
                        style={{
                          backgroundColor:
                            e.status === "active"
                              ? "#2A1215"
                              : e.status === "investigating"
                              ? "#28200F"
                              : "#10261E",
                          borderColor:
                            e.status === "active"
                              ? "var(--color-critical)"
                              : e.status === "investigating"
                              ? "var(--color-warning)"
                              : "var(--color-success)",
                          color:
                            e.status === "active"
                              ? "var(--color-critical)"
                              : e.status === "investigating"
                              ? "var(--color-warning)"
                              : "var(--color-success)",
                        }}
                      >
                        {e.status}
                      </span>
                    </td>
                    <td style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>
                      {formatDateTime(e.timestamp)}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
