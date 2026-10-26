import React from "react";
import { SessionStats, ProtocolMetric, SeverityDistribution } from "../../types/stats";
import { SecurityEvent } from "../../types/event";
import { GatewayInfo, DriverStatus } from "../../types/network";
import { formatBytes, formatDuration, formatDateTime } from "../../lib/formatters";
import { SecurityClearEmptyState } from "../../components/EmptyState";
import {
  FileText,
  Download,
  ShieldAlert,
  Activity,
  Globe,
  FlaskConical,
  CheckCircle2,
  AlertTriangle,
  Info,
} from "lucide-react";

interface ReportsPageProps {
  sessionStats: SessionStats;
  protocolMetrics: ProtocolMetric[];
  severityDist: SeverityDistribution;
  events: SecurityEvent[];
  gatewayInfo: GatewayInfo;
  driverStatus: DriverStatus;
  onExportJson: () => void;
  onExportCsv: () => void;
}

export const ReportsPage: React.FC<ReportsPageProps> = ({
  sessionStats,
  protocolMetrics,
  severityDist,
  events,
  gatewayInfo,
  driverStatus,
  onExportJson,
  onExportCsv,
}) => {
  return (
    <div
      style={{
        flex: 1,
        padding: "20px 24px",
        display: "flex",
        flexDirection: "column",
        gap: "20px",
        overflowY: "auto",
        height: "100%",
      }}
    >
      {/* Report Header */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          borderBottom: "1px solid var(--color-border)",
          paddingBottom: "16px",
        }}
      >
        <div>
          <h2 style={{ fontSize: "18px", fontWeight: 700, color: "var(--color-text-primary)" }}>
            Local Network Security Audit Report
          </h2>
          <div style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>
            Generated locally by SHADOWSENTRY • {formatDateTime(new Date().toISOString())}
          </div>
        </div>

        <div style={{ display: "flex", gap: "10px" }}>
          <button onClick={onExportJson}>
            <Download size={13} />
            <span>Export Sanitized JSON</span>
          </button>
          <button className="primary" onClick={onExportCsv}>
            <Download size={13} />
            <span>Export Sanitized CSV</span>
          </button>
        </div>
      </div>

      {/* Executive Summary Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "14px" }}>
        <div style={{ backgroundColor: "var(--color-surface)", border: "1px solid var(--color-border)", borderRadius: "var(--radius-sm)", padding: "14px 16px" }}>
          <div style={{ fontSize: "11px", color: "var(--color-text-muted)", textTransform: "uppercase" }}>Monitored Interface</div>
          <div style={{ fontSize: "15px", fontWeight: 600, color: "var(--color-text-primary)", marginTop: "4px" }}>
            {sessionStats.interface_name}
          </div>
          <div style={{ fontSize: "11px", color: "var(--color-text-secondary)", marginTop: "2px" }}>
            Backend: {sessionStats.capture_backend}
          </div>
        </div>

        <div style={{ backgroundColor: "var(--color-surface)", border: "1px solid var(--color-border)", borderRadius: "var(--radius-sm)", padding: "14px 16px" }}>
          <div style={{ fontSize: "11px", color: "var(--color-text-muted)", textTransform: "uppercase" }}>Traffic Volume Observed</div>
          <div style={{ fontSize: "15px", fontWeight: 600, color: "var(--color-accent-primary)", marginTop: "4px" }}>
            {formatBytes(sessionStats.total_bytes)}
          </div>
          <div style={{ fontSize: "11px", color: "var(--color-text-secondary)", marginTop: "2px" }}>
            {sessionStats.total_packets.toLocaleString()} packets parsed safely
          </div>
        </div>

        <div style={{ backgroundColor: "var(--color-surface)", border: "1px solid var(--color-border)", borderRadius: "var(--radius-sm)", padding: "14px 16px" }}>
          <div style={{ fontSize: "11px", color: "var(--color-text-muted)", textTransform: "uppercase" }}>Threat Findings</div>
          <div style={{ fontSize: "15px", fontWeight: 600, color: events.length > 0 ? "var(--color-critical)" : "var(--color-success)", marginTop: "4px" }}>
            {events.length} Detections Logged
          </div>
          <div style={{ fontSize: "11px", color: "var(--color-text-secondary)", marginTop: "2px" }}>
            {severityDist.critical} Critical • {severityDist.high} High • {severityDist.medium} Med
          </div>
        </div>

        <div style={{ backgroundColor: "var(--color-surface)", border: "1px solid var(--color-border)", borderRadius: "var(--radius-sm)", padding: "14px 16px" }}>
          <div style={{ fontSize: "11px", color: "var(--color-text-muted)", textTransform: "uppercase" }}>Gateway Identity</div>
          <div style={{ fontSize: "14px", fontWeight: 600, color: "var(--color-text-primary)", fontFamily: "var(--font-mono)", marginTop: "4px" }}>
            {gatewayInfo.ip_address}
          </div>
          <div style={{ fontSize: "11px", color: "var(--color-text-secondary)", marginTop: "2px" }}>
            MAC: {gatewayInfo.mac_address}
          </div>
        </div>
      </div>

      {/* Section 1: Threat Detection Summary Table */}
      <div style={{ backgroundColor: "var(--color-surface)", border: "1px solid var(--color-border)", borderRadius: "var(--radius-md)", padding: "16px" }}>
        <h3 style={{ fontSize: "14px", fontWeight: 600, color: "var(--color-text-primary)", marginBottom: "4px" }}>
          1. Security Threat Detection Summary
        </h3>
        <p style={{ fontSize: "11px", color: "var(--color-text-muted)", marginBottom: "14px" }}>
          Observed heuristic anomalies and rule triggers recorded locally
        </p>

        {events.length === 0 ? (
          <SecurityClearEmptyState
            title="Zero Threat Indicators Detected"
            description="All monitored sessions and packet flows conformed to security baseline rules during this observation window."
            badgeText="Forensic Report Ready • Zero Anomalies Logged"
            iconType="success"
            compact
          />
        ) : (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Detection Rule</th>
                  <th>Observed Finding</th>
                  <th>Origin</th>
                  <th>Target</th>
                  <th>Confidence</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => (
                  <tr key={e.event_id}>
                    <td>
                      <span
                        className="badge"
                        style={{
                          backgroundColor:
                            e.severity === "critical"
                              ? "#2A1215"
                              : e.severity === "high"
                              ? "#2A1810"
                              : "#28200F",
                          borderColor:
                            e.severity === "critical"
                              ? "var(--color-critical)"
                              : e.severity === "high"
                              ? "var(--color-high)"
                              : "var(--color-warning)",
                          color:
                            e.severity === "critical"
                              ? "var(--color-critical)"
                              : e.severity === "high"
                              ? "var(--color-high)"
                              : "var(--color-warning)",
                        }}
                      >
                        {e.severity}
                      </span>
                    </td>
                    <td style={{ fontWeight: 600 }}>{e.rule_name}</td>
                    <td style={{ maxWidth: "340px", overflow: "hidden", textOverflow: "ellipsis" }}>{e.what_observed}</td>
                    <td className="font-mono">{e.source_ip || "Local"}</td>
                    <td className="font-mono">{e.dest_ip || "—"}</td>
                    <td className="font-mono">{Math.round(e.confidence_score * 100)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Section 2: Traffic Composition */}
      <div style={{ backgroundColor: "var(--color-surface)", border: "1px solid var(--color-border)", borderRadius: "var(--radius-md)", padding: "16px" }}>
        <h3 style={{ fontSize: "14px", fontWeight: 600, color: "var(--color-text-primary)", marginBottom: "4px" }}>
          2. Observed Protocol Breakdown
        </h3>
        <p style={{ fontSize: "11px", color: "var(--color-text-muted)", marginBottom: "14px" }}>
          Breakdown of observed Layer 3 and Layer 4 protocols
        </p>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: "10px" }}>
          {protocolMetrics.map((m) => (
            <div key={m.protocol} style={{ padding: "10px", backgroundColor: "var(--color-bg)", borderRadius: "var(--radius-sm)", border: "1px solid var(--color-border-subtle)" }}>
              <div style={{ fontSize: "11px", color: m.color, fontWeight: 700 }}>{m.protocol}</div>
              <div style={{ fontSize: "18px", fontWeight: 700, fontFamily: "var(--font-mono)", color: "var(--color-text-primary)", marginTop: "2px" }}>
                {m.percentage}%
              </div>
              <div style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>
                {m.packet_count.toLocaleString()} packets ({formatBytes(m.byte_count)})
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Section 3: Legal, Ethical, and Visibility Limitations Notice */}
      <div
        style={{
          padding: "14px 16px",
          backgroundColor: "#151B24",
          border: "1px solid var(--color-border)",
          borderRadius: "var(--radius-sm)",
          fontSize: "11px",
          color: "var(--color-text-secondary)",
          lineHeight: 1.5,
        }}
      >
        <div style={{ fontWeight: 600, color: "var(--color-text-primary)", marginBottom: "4px" }}>
          Forensic Transparency & Switched Network Constraints
        </div>
        <div>
          This report reflects telemetry captured on the selected local network interface. On modern switched Ethernet
          or Wi-Fi networks with client isolation, workstations generally cannot observe unicast traffic between other
          devices unless network mirroring, port spanning, or router authorization is configured. End-to-end encrypted
          payloads (TLS/HTTPS, DoH, VPNs) remain confidential by design; SHADOWSENTRY monitors protocol metadata,
          handshake headers, and network configuration changes only.
        </div>
      </div>
    </div>
  );
};
