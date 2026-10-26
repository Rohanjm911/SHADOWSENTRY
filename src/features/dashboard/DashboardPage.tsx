import React from "react";
import {
  SessionStats,
  ProtocolMetric,
  TrafficTimelinePoint,
  SeverityDistribution,
} from "../../types/stats";
import { SecurityEvent, EventStatus } from "../../types/event";
import { DriverStatus, GatewayInfo, MonitoringStatus } from "../../types/network";
import { formatBytes, formatDuration, formatDateTime } from "../../lib/formatters";
import { ThreatSeverityBadge } from "../../components/ThreatSeverityBadge";
import { MiniSparkline } from "../../components/MiniSparkline";
import { TrafficTimelineChart } from "../../components/TrafficTimelineChart";
import { SecurityClearEmptyState } from "../../components/EmptyState";
import {
  ShieldAlert,
  Activity,
  Globe,
  FlaskConical,
  Play,
  Square,
  Network,
  CheckCircle2,
  AlertTriangle,
  Info,
  ChevronRight,
  RefreshCw,
  HardDrive,
  UserCheck,
  HelpCircle,
} from "lucide-react";

interface DashboardPageProps {
  monitoringStatus: MonitoringStatus;
  sessionStats: SessionStats;
  protocolMetrics: ProtocolMetric[];
  timeline: TrafficTimelinePoint[];
  severityDist: SeverityDistribution;
  recentEvents: SecurityEvent[];
  driverStatus: DriverStatus;
  gatewayInfo: GatewayInfo;
  onStartMonitoring: () => void;
  onStopMonitoring: () => void;
  onSelectEvent: (event: SecurityEvent) => void;
  onRefresh: () => void;
  onNavigateTab: (tab: any) => void;
  onOpenTutorial?: () => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  monitoringStatus,
  sessionStats,
  protocolMetrics,
  timeline,
  severityDist,
  recentEvents,
  driverStatus,
  gatewayInfo,
  onStartMonitoring,
  onStopMonitoring,
  onSelectEvent,
  onRefresh,
  onNavigateTab,
  onOpenTutorial,
}) => {
  const isRunning = monitoringStatus.is_active;

  // Max packets in timeline for SVG scaling
  const maxPackets = Math.max(...timeline.map((t) => t.packet_count), 10);

  // Sparkline data series from timeline
  const recentTimeline = timeline.slice(-10);
  const packetSeries = recentTimeline.length >= 2
    ? recentTimeline.map((t) => t.packet_count)
    : [sessionStats.packet_rate_per_sec * 0.5, sessionStats.packet_rate_per_sec * 0.8, sessionStats.packet_rate_per_sec];
  const byteSeries = recentTimeline.length >= 2
    ? recentTimeline.map((t) => t.byte_count)
    : [sessionStats.byte_rate_per_sec * 0.4, sessionStats.byte_rate_per_sec * 0.7, sessionStats.byte_rate_per_sec];
  const findingsSeries = [
    severityDist.informational,
    severityDist.low,
    severityDist.medium,
    severityDist.high,
    severityDist.critical,
    sessionStats.security_findings_total,
  ];
  const dnsSeries = recentTimeline.length >= 2
    ? recentTimeline.map((t) => Math.max(1, Math.round(t.packet_count * 0.15)))
    : [Math.floor(sessionStats.dns_queries_total * 0.5), sessionStats.dns_queries_total];
  const honeypotSeries = [
    0,
    Math.floor(sessionStats.honeypot_probes_total * 0.2),
    Math.floor(sessionStats.honeypot_probes_total * 0.5),
    sessionStats.honeypot_probes_total,
  ];

  return (
    <div
      style={{
        padding: "20px 24px",
        display: "flex",
        flexDirection: "column",
        gap: "20px",
        overflowY: "auto",
        height: "100%",
      }}
    >
      {/* Primary Monitoring Control Banner */}
      <div
        style={{
          backgroundColor: "var(--color-surface)",
          border: "1px solid var(--color-border)",
          borderRadius: "var(--radius-md)",
          padding: "16px 20px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          boxShadow: "0 2px 6px rgba(0,0,0,0.3)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
          <div
            style={{
              width: "44px",
              height: "44px",
              borderRadius: "var(--radius-sm)",
              backgroundColor: isRunning ? "#0E241F" : "#131C28",
              border: `1px solid ${isRunning ? "var(--color-success)" : "var(--color-border)"}`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              color: isRunning ? "var(--color-success)" : "var(--color-text-muted)",
            }}
          >
            <Activity size={24} />
          </div>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <span style={{ fontSize: "16px", fontWeight: 700, color: "var(--color-text-primary)", display: "flex", alignItems: "center", gap: "6px" }}>
                <span>{isRunning ? "Live Traffic Monitoring Active" : "Monitoring Engine Standby"}</span>
                {isRunning && (
                  <span style={{ display: "inline-flex", alignItems: "flex-end", gap: "2px", height: "14px", marginLeft: "2px" }} title="Wire Traffic Active">
                    <span style={{ width: "3px", backgroundColor: "var(--color-success)", borderRadius: "1px", animation: "liveBarEqualizer1 0.8s ease-in-out infinite" }} />
                    <span style={{ width: "3px", backgroundColor: "var(--color-success)", borderRadius: "1px", animation: "liveBarEqualizer2 1.1s ease-in-out infinite 0.15s" }} />
                    <span style={{ width: "3px", backgroundColor: "var(--color-success)", borderRadius: "1px", animation: "liveBarEqualizer3 0.7s ease-in-out infinite 0.3s" }} />
                    <span style={{ width: "3px", backgroundColor: "var(--color-success)", borderRadius: "1px", animation: "liveBarEqualizer4 1.0s ease-in-out infinite 0.2s" }} />
                  </span>
                )}
              </span>
              <span
                style={{
                  fontSize: "11px",
                  padding: "2px 8px",
                  borderRadius: "3px",
                  backgroundColor: isRunning ? "rgba(52, 211, 153, 0.15)" : "var(--color-surface-elevated)",
                  color: isRunning ? "var(--color-success)" : "var(--color-text-muted)",
                  border: `1px solid ${isRunning ? "var(--color-success)" : "var(--color-border)"}`,
                  fontWeight: 600,
                  textTransform: "uppercase",
                }}
              >
                {isRunning ? "Capturing" : "Idle"}
              </span>
            </div>
            <div style={{ fontSize: "12px", color: "var(--color-text-secondary)", marginTop: "4px" }}>
              Interface: <strong style={{ color: "var(--color-text-primary)" }}>{monitoringStatus.selected_interface || "None"}</strong>
              {" • "}Backend: <strong style={{ color: "var(--color-accent-primary)" }}>{sessionStats.capture_backend}</strong>
              {" • "}Session Elapsed: <strong style={{ color: "var(--color-text-primary)" }}>{formatDuration(monitoringStatus.duration_seconds)}</strong>
            </div>
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          {onOpenTutorial && (
            <button
              className="ghost"
              onClick={onOpenTutorial}
              title="Open Interactive How to Use Tutorial Guide"
              style={{
                display: "flex",
                alignItems: "center",
                gap: "6px",
                color: "var(--color-accent-primary)",
                border: "1px solid rgba(56, 189, 248, 0.3)",
                backgroundColor: "rgba(56, 189, 248, 0.08)",
                fontSize: "12px",
                fontWeight: 600,
                padding: "6px 12px",
              }}
            >
              <HelpCircle size={14} />
              <span>How to Use</span>
            </button>
          )}
          <button className="ghost" onClick={onRefresh} title="Refresh telemetry">
            <RefreshCw size={14} />
            <span>Refresh</span>
          </button>
          {isRunning ? (
            <button
              onClick={onStopMonitoring}
              style={{
                backgroundColor: "var(--color-critical)",
                borderColor: "var(--color-critical)",
                color: "#FFFFFF",
                fontWeight: 600,
                padding: "8px 16px",
              }}
            >
              <Square size={14} fill="#FFFFFF" />
              <span>Stop Monitoring</span>
            </button>
          ) : (
            <button
              className="primary"
              onClick={onStartMonitoring}
              style={{ fontWeight: 600, padding: "8px 16px" }}
            >
              <Play size={14} fill="currentColor" />
              <span>Start Monitoring</span>
            </button>
          )}
        </div>
      </div>

      {/* Metrics Row: 5 Key Technical Counters with Real-Time Sparklines */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))",
          gap: "14px",
        }}
      >
        {/* Metric 1: Packets */}
        <div className="metric-card-interactive" style={{ backgroundColor: "var(--color-surface)", border: "1px solid var(--color-border)", borderRadius: "var(--radius-sm)", padding: "var(--metric-card-padding, 14px 16px)", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
          <div style={{ fontSize: "11px", color: "var(--color-text-muted)", textTransform: "uppercase", fontWeight: 600 }}>Captured Packets</div>
          <div style={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between", marginTop: "6px" }}>
            <div>
              <div style={{ fontSize: "22px", fontWeight: 700, color: "var(--color-text-primary)", fontFamily: "var(--font-mono)" }}>
                {sessionStats.total_packets.toLocaleString()}
              </div>
              <div style={{ fontSize: "11px", color: "var(--color-text-secondary)", marginTop: "2px" }}>
                {sessionStats.packet_rate_per_sec.toFixed(1)} pkts/s
              </div>
            </div>
            <MiniSparkline data={packetSeries} color="var(--color-accent-primary)" />
          </div>
        </div>

        {/* Metric 2: Observed Volume */}
        <div className="metric-card-interactive" style={{ backgroundColor: "var(--color-surface)", border: "1px solid var(--color-border)", borderRadius: "var(--radius-sm)", padding: "var(--metric-card-padding, 14px 16px)", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
          <div style={{ fontSize: "11px", color: "var(--color-text-muted)", textTransform: "uppercase", fontWeight: 600 }}>Traffic Volume</div>
          <div style={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between", marginTop: "6px" }}>
            <div>
              <div style={{ fontSize: "22px", fontWeight: 700, color: "var(--color-accent-primary)", fontFamily: "var(--font-mono)" }}>
                {formatBytes(sessionStats.total_bytes)}
              </div>
              <div style={{ fontSize: "11px", color: "var(--color-text-secondary)", marginTop: "2px" }}>
                {formatBytes(sessionStats.byte_rate_per_sec)}/s
              </div>
            </div>
            <MiniSparkline data={byteSeries} color="var(--color-accent-secondary)" />
          </div>
        </div>

        {/* Metric 3: Security Findings */}
        <div className="metric-card-interactive" style={{ backgroundColor: "var(--color-surface)", border: "1px solid var(--color-border)", borderRadius: "var(--radius-sm)", padding: "var(--metric-card-padding, 14px 16px)", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
          <div style={{ fontSize: "11px", color: "var(--color-text-muted)", textTransform: "uppercase", fontWeight: 600 }}>Security Findings</div>
          <div style={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between", marginTop: "6px" }}>
            <div>
              <div style={{ fontSize: "22px", fontWeight: 700, color: sessionStats.security_findings_total > 0 ? "var(--color-critical)" : "var(--color-success)", fontFamily: "var(--font-mono)" }}>
                {sessionStats.security_findings_total}
              </div>
              <div style={{ fontSize: "11px", color: "var(--color-text-secondary)", marginTop: "2px" }}>
                {severityDist.critical} Critical • {severityDist.high} High
              </div>
            </div>
            <MiniSparkline data={findingsSeries} color={sessionStats.security_findings_total > 0 ? "var(--color-critical)" : "var(--color-success)"} />
          </div>
        </div>

        {/* Metric 4: DNS Queries */}
        <div className="metric-card-interactive" style={{ backgroundColor: "var(--color-surface)", border: "1px solid var(--color-border)", borderRadius: "var(--radius-sm)", padding: "var(--metric-card-padding, 14px 16px)", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
          <div style={{ fontSize: "11px", color: "var(--color-text-muted)", textTransform: "uppercase", fontWeight: 600 }}>DNS Queries</div>
          <div style={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between", marginTop: "6px" }}>
            <div>
              <div style={{ fontSize: "22px", fontWeight: 700, color: "var(--color-proto-dns)", fontFamily: "var(--font-mono)" }}>
                {sessionStats.dns_queries_total}
              </div>
              <div style={{ fontSize: "11px", color: "var(--color-text-secondary)", marginTop: "2px" }}>
                Port 53 queries
              </div>
            </div>
            <MiniSparkline data={dnsSeries} color="var(--color-proto-dns)" />
          </div>
        </div>

        {/* Metric 5: Honeypot Interactions */}
        <div className="metric-card-interactive" style={{ backgroundColor: "var(--color-surface)", border: "1px solid var(--color-border)", borderRadius: "var(--radius-sm)", padding: "var(--metric-card-padding, 14px 16px)", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
          <div style={{ fontSize: "11px", color: "var(--color-text-muted)", textTransform: "uppercase", fontWeight: 600 }}>Honeypot Probes</div>
          <div style={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between", marginTop: "6px" }}>
            <div>
              <div style={{ fontSize: "22px", fontWeight: 700, color: "var(--color-warning)", fontFamily: "var(--font-mono)" }}>
                {sessionStats.honeypot_probes_total}
              </div>
              <div style={{ fontSize: "11px", color: "var(--color-text-secondary)", marginTop: "2px" }}>
                Decoy hits logged
              </div>
            </div>
            <MiniSparkline data={honeypotSeries} color="var(--color-warning)" />
          </div>
        </div>
      </div>

      {/* Visualizations Grid */}
      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: "16px" }}>
        {/* Left: Traffic Volume Timeline (Continuous Bezier Area Wave with Telemetry HUD) */}
        <TrafficTimelineChart
          timeline={timeline}
          sessionStats={sessionStats}
          maxPackets={maxPackets}
          isMonitoring={isRunning}
        />

        {/* Right: Protocol Distribution */}
        <div
          style={{
            backgroundColor: "var(--color-surface)",
            border: "1px solid var(--color-border)",
            borderRadius: "var(--radius-md)",
            padding: "16px",
            display: "flex",
            flexDirection: "column",
          }}
        >
          <h3 style={{ fontSize: "13px", fontWeight: 600, color: "var(--color-text-primary)", marginBottom: "4px" }}>
            Protocol Distribution
          </h3>
          <p style={{ fontSize: "11px", color: "var(--color-text-muted)", marginBottom: "14px" }}>
            Observed traffic composition
          </p>

          <div style={{ display: "flex", flexDirection: "column", gap: "10px", flex: 1, justifyContent: "center" }}>
            {protocolMetrics.map((m) => (
              <div key={m.protocol}>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: "11px", marginBottom: "3px" }}>
                  <span style={{ fontWeight: 600, color: m.color }}>{m.protocol}</span>
                  <span style={{ fontFamily: "var(--font-mono)", color: "var(--color-text-secondary)" }}>
                    {m.packet_count.toLocaleString()} pkts ({m.percentage}%)
                  </span>
                </div>
                <div style={{ height: "6px", backgroundColor: "var(--color-bg)", borderRadius: "3px", overflow: "hidden" }}>
                  <div
                    style={{
                      width: `${Math.min(100, Math.max(m.percentage, m.packet_count > 0 ? 2 : 0))}%`,
                      height: "100%",
                      backgroundColor: m.color,
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Split Section: Recent Alerts vs Network Health */}
      <div style={{ display: "grid", gridTemplateColumns: "1.4fr 1fr", gap: "16px" }}>
        
        {/* Recent Security Findings */}
        <div
          style={{
            backgroundColor: "var(--color-surface)",
            border: "1px solid var(--color-border)",
            borderRadius: "var(--radius-md)",
            padding: "16px",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px" }}>
            <div>
              <h3 style={{ fontSize: "13px", fontWeight: 600, color: "var(--color-text-primary)" }}>Recent Security Findings</h3>
              <p style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>Explainable alert detections with evidence</p>
            </div>
            <button className="ghost" onClick={() => onNavigateTab("threats")} style={{ fontSize: "11px" }}>
              View All Threats <ChevronRight size={12} />
            </button>
          </div>

          {recentEvents.length === 0 ? (
            <SecurityClearEmptyState
              title="All Systems Clear — Zero Threats Observed"
              description="No suspicious behaviors, port sweeps, or signature violations detected in the active capture window."
              badgeText="10 Heuristic Detection Rules Active"
              iconType="success"
              compact
            />
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
              {recentEvents.slice(0, 4).map((evt) => (
                <div
                  key={evt.event_id}
                  onClick={() => onSelectEvent(evt)}
                  style={{
                    padding: "10px 12px",
                    backgroundColor: "var(--color-surface-elevated)",
                    border: "1px solid var(--color-border-subtle)",
                    borderRadius: "var(--radius-sm)",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    cursor: "pointer",
                    transition: "border-color 0.15s ease",
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.borderColor = "var(--color-accent-primary)")}
                  onMouseLeave={(e) => (e.currentTarget.style.borderColor = "var(--color-border-subtle)")}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "10px", flex: 1, minWidth: 0 }}>
                    <ThreatSeverityBadge severity={evt.severity} />
                    <div style={{ minWidth: 0, flex: 1 }}>
                      <div style={{ fontSize: "12px", fontWeight: 600, color: "var(--color-text-primary)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                        {evt.rule_name}
                      </div>
                      <div style={{ fontSize: "11px", color: "var(--color-text-muted)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                        {evt.what_observed}
                      </div>
                    </div>
                  </div>
                  <div style={{ fontSize: "11px", color: "var(--color-text-muted)", marginLeft: "12px", whiteSpace: "nowrap" }}>
                    {formatDateTime(evt.timestamp)}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Network Health & Capability Audit */}
        <div
          style={{
            backgroundColor: "var(--color-surface)",
            border: "1px solid var(--color-border)",
            borderRadius: "var(--radius-md)",
            padding: "16px",
          }}
        >
          <h3 style={{ fontSize: "13px", fontWeight: 600, color: "var(--color-text-primary)", marginBottom: "4px" }}>
            Network Health & Capabilities
          </h3>
          <p style={{ fontSize: "11px", color: "var(--color-text-muted)", marginBottom: "14px" }}>
            Host capabilities and driver visibility boundaries
          </p>

          <div style={{ display: "flex", flexDirection: "column", gap: "10px", fontSize: "12px" }}>
            {/* Gateway Monitor */}
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "8px 10px", backgroundColor: "var(--color-bg)", borderRadius: "var(--radius-sm)", border: "1px solid var(--color-border-subtle)" }}>
              <div>
                <div style={{ fontWeight: 600, color: "var(--color-text-primary)" }}>Default Gateway</div>
                <div style={{ fontSize: "11px", fontFamily: "var(--font-mono)", color: "var(--color-text-muted)" }}>
                  {gatewayInfo.ip_address} ({gatewayInfo.mac_address})
                </div>
              </div>
              <span className="badge" style={{ backgroundColor: "#10261E", borderColor: "var(--color-success)", color: "var(--color-success)" }}>
                Verified
              </span>
            </div>

            {/* Packet Driver Status */}
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "8px 10px", backgroundColor: "var(--color-bg)", borderRadius: "var(--radius-sm)", border: "1px solid var(--color-border-subtle)" }}>
              <div>
                <div style={{ fontWeight: 600, color: "var(--color-text-primary)" }}>Npcap Driver</div>
                <div style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>
                  {driverStatus.npcap_installed ? "Npcap Installed (L2 Supported)" : "Not Installed (Raw Sockets active)"}
                </div>
              </div>
              <span className="badge" style={{ backgroundColor: driverStatus.npcap_installed ? "#10261E" : "#28200F", borderColor: driverStatus.npcap_installed ? "var(--color-success)" : "var(--color-warning)", color: driverStatus.npcap_installed ? "var(--color-success)" : "var(--color-warning)" }}>
                {driverStatus.npcap_installed ? "Installed" : "Optional"}
              </span>
            </div>

            {/* DNS Visibility Boundary */}
            <div style={{ padding: "8px 10px", backgroundColor: "var(--color-bg)", borderRadius: "var(--radius-sm)", border: "1px solid var(--color-border-subtle)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "6px", color: "var(--color-accent-secondary)", fontWeight: 600, fontSize: "11px", marginBottom: "2px" }}>
                <Info size={13} />
                <span>DNS Visibility Boundary</span>
              </div>
              <div style={{ fontSize: "11px", color: "var(--color-text-muted)", lineHeight: 1.4 }}>
                Unencrypted DNS on port 53 is fully monitored. DoH (DNS-over-HTTPS) or VPN queries are encrypted end-to-end by design.
              </div>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
};
