import React, { useState } from "react";
import { HoneypotServiceState, HoneypotInteractionLog, HoneypotSimulationResult } from "../../types/honeypot";
import { ConfirmationDialog } from "../../components/ConfirmationDialog";
import { formatDateTime } from "../../lib/formatters";
import { TableEmptyRow } from "../../components/EmptyState";
import {
  FlaskConical,
  Play,
  Square,
  Globe,
  Lock,
  Terminal,
  AlertTriangle,
  Info,
  ShieldCheck,
  CheckCircle2,
  Zap,
  Copy,
  Check,
  X,
  Radio,
  ArrowRight,
  ShieldAlert,
  Loader2,
} from "lucide-react";

interface HoneypotLabPageProps {
  services: HoneypotServiceState[];
  logs: HoneypotInteractionLog[];
  onStartService: (serviceType: string, port: number, allowLan: boolean) => Promise<void>;
  onStopService: (serviceType: string) => Promise<void>;
  onSimulateProbe?: (serviceType: string, probeTarget?: string) => Promise<HoneypotSimulationResult>;
  onRefresh: () => void;
}

export const HoneypotLabPage: React.FC<HoneypotLabPageProps> = ({
  services,
  logs,
  onStartService,
  onStopService,
  onSimulateProbe,
  onRefresh,
}) => {
  const [pendingLanService, setPendingLanService] = useState<{
    serviceType: string;
    port: number;
  } | null>(null);

  const [portInputs, setPortInputs] = useState<{ [key: string]: number }>({
    http_decoy: 8088,
    admin_portal: 8443,
    ssh_banner: 2222,
  });

  const [lanToggles, setLanToggles] = useState<{ [key: string]: boolean }>({
    http_decoy: false,
    admin_portal: false,
    ssh_banner: false,
  });

  const [isSimulating, setIsSimulating] = useState<string | null>(null);
  const [simulationResult, setSimulationResult] = useState<HoneypotSimulationResult | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const handleStartClicked = (serviceType: string) => {
    const port = portInputs[serviceType] || (serviceType === "http_decoy" ? 8088 : serviceType === "admin_portal" ? 8443 : 2222);
    const allowLan = Boolean(lanToggles[serviceType]);

    if (allowLan) {
      setPendingLanService({ serviceType, port });
    } else {
      onStartService(serviceType, port, false);
    }
  };

  const handleConfirmLanExposure = () => {
    if (pendingLanService) {
      onStartService(pendingLanService.serviceType, pendingLanService.port, true);
      setPendingLanService(null);
    }
  };

  const handleFireProbe = async (serviceType: string, targetPath?: string) => {
    if (!onSimulateProbe) return;
    setIsSimulating(`${serviceType}-${targetPath || "default"}`);
    try {
      const res = await onSimulateProbe(serviceType, targetPath);
      setSimulationResult(res);
      onRefresh();
    } catch (err: any) {
      alert(`Simulation failed: ${err?.message || err}`);
    } finally {
      setIsSimulating(null);
    }
  };

  const handleCopyCommand = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const getServiceIcon = (type: string) => {
    switch (type) {
      case "http_decoy":
        return <Globe size={20} style={{ color: "var(--color-accent-primary)" }} />;
      case "admin_portal":
        return <Lock size={20} style={{ color: "var(--color-warning)" }} />;
      case "ssh_banner":
        return <Terminal size={20} style={{ color: "var(--color-success)" }} />;
      default:
        return <FlaskConical size={20} />;
    }
  };

  return (
    <div
      style={{
        flex: 1,
        display: "flex",
        flexDirection: "column",
        padding: "16px 20px",
        gap: "16px",
        overflowY: "auto",
        height: "100%",
      }}
    >
      {/* Top Banner: Isolation and Safety Guidelines */}
      <div
        style={{
          padding: "12px 16px",
          backgroundColor: "#1B232E",
          border: "1px solid var(--color-border)",
          borderRadius: "var(--radius-sm)",
          display: "flex",
          alignItems: "flex-start",
          gap: "12px",
          fontSize: "12px",
        }}
      >
        <ShieldCheck size={20} style={{ color: "var(--color-success)", marginTop: "2px", flexShrink: 0 }} />
        <div style={{ flex: 1, lineHeight: 1.5 }}>
          <strong style={{ color: "var(--color-text-primary)" }}>Controlled Honeypot Security Lab:</strong>{" "}
          <span style={{ color: "var(--color-text-secondary)" }}>
            These protocol emulators simulate high-value decoy targets to safely observe unauthorized probes. Services
            bind to <code>127.0.0.1</code> (loopback only) by default, never execute client input, and reject unauthorized credentials safely.
            Use the <strong>1-Click Attack Simulator</strong> or terminal quick-commands below to trigger live detection.
          </span>
        </div>
      </div>

      {/* Honeypot Service Cards Grid */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: "14px" }}>
        {services.map((svc) => {
          const isRunning = svc.is_running;
          const portVal = portInputs[svc.service_type] ?? svc.port;
          const isLan = Boolean(lanToggles[svc.service_type] ?? svc.allow_lan);

          return (
            <div
              key={svc.service_type}
              style={{
                backgroundColor: "var(--color-surface)",
                border: `1px solid ${isRunning ? "var(--color-success)" : "var(--color-border)"}`,
                borderRadius: "var(--radius-md)",
                padding: "16px",
                display: "flex",
                flexDirection: "column",
                justifyContent: "space-between",
                gap: "14px",
                boxShadow: isRunning ? "0 0 14px rgba(52, 211, 153, 0.14)" : "none",
                transition: "all 0.2s ease",
              }}
            >
              <div>
                {/* Header */}
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "8px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <div style={{ padding: "6px", backgroundColor: "var(--color-surface-elevated)", borderRadius: "var(--radius-sm)" }}>
                      {getServiceIcon(svc.service_type)}
                    </div>
                    <div>
                      <h3 style={{ fontSize: "14px", fontWeight: 600, color: "var(--color-text-primary)" }}>
                        {svc.name}
                      </h3>
                      <div style={{ fontSize: "11px", color: isRunning ? "var(--color-success)" : "var(--color-text-muted)", display: "flex", alignItems: "center", gap: "5px" }}>
                        {isRunning && (
                          <span
                            style={{
                              width: 6,
                              height: 6,
                              borderRadius: "50%",
                              backgroundColor: "var(--color-success)",
                              boxShadow: "0 0 6px var(--color-success)",
                              display: "inline-block",
                            }}
                          />
                        )}
                        <span>{svc.status_message}</span>
                      </div>
                    </div>
                  </div>

                  <span
                    className="badge"
                    style={{
                      backgroundColor: isRunning ? "#10261E" : "#1B232E",
                      borderColor: isRunning ? "var(--color-success)" : "var(--color-border)",
                      color: isRunning ? "var(--color-success)" : "var(--color-text-muted)",
                      display: "flex",
                      alignItems: "center",
                      gap: "4px",
                    }}
                  >
                    {isRunning ? "ARMED & LISTENING" : "STOPPED"}
                  </span>
                </div>

                <p style={{ fontSize: "12px", color: "var(--color-text-secondary)", marginBottom: "12px", lineHeight: 1.4 }}>
                  {svc.description}
                </p>

                {/* Configuration Inputs */}
                <div style={{ display: "flex", flexDirection: "column", gap: "8px", backgroundColor: "var(--color-bg)", padding: "10px", borderRadius: "var(--radius-sm)", border: "1px solid var(--color-border-subtle)", fontSize: "12px" }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                    <label htmlFor={`port-${svc.service_type}`} style={{ color: "var(--color-text-secondary)" }}>Listening Port:</label>
                    <input
                      id={`port-${svc.service_type}`}
                      type="number"
                      disabled={isRunning}
                      value={portVal}
                      onChange={(e) => setPortInputs({ ...portInputs, [svc.service_type]: parseInt(e.target.value) || 0 })}
                      style={{ width: "90px", padding: "3px 6px", fontFamily: "var(--font-mono)" }}
                    />
                  </div>

                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                    <label htmlFor={`lan-${svc.service_type}`} style={{ color: "var(--color-text-secondary)" }}>Reachability Scope:</label>
                    <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                      <input
                        id={`lan-${svc.service_type}`}
                        type="checkbox"
                        disabled={isRunning}
                        checked={isLan}
                        onChange={(e) => setLanToggles({ ...lanToggles, [svc.service_type]: e.target.checked })}
                      />
                      <span style={{ fontSize: "11px", color: isLan ? "var(--color-warning)" : "var(--color-text-muted)" }}>
                        {isLan ? "Expose to LAN (0.0.0.0)" : "Loopback Only (127.0.0.1)"}
                      </span>
                    </div>
                  </div>

                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "11px", color: "var(--color-text-muted)", borderTop: "1px solid var(--color-border-subtle)", paddingTop: "6px" }}>
                    <span>Interactions Observed:</span>
                    <strong
                      style={{
                        color: svc.total_connections_seen > 0 ? "var(--color-success)" : "var(--color-text-primary)",
                        fontFamily: "var(--font-mono)",
                        backgroundColor: svc.total_connections_seen > 0 ? "rgba(52, 211, 153, 0.15)" : "transparent",
                        padding: "1px 6px",
                        borderRadius: "3px",
                      }}
                    >
                      {svc.total_connections_seen} hits
                    </strong>
                  </div>
                </div>

                {/* 1-Click Attack Simulator Action Pills */}
                <div style={{ marginTop: "10px" }}>
                  <div style={{ fontSize: "10.5px", fontWeight: 600, color: "var(--color-text-muted)", marginBottom: "5px", textTransform: "uppercase", letterSpacing: "0.04em" }}>
                    1-Click Simulation Probes:
                  </div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                    {svc.service_type === "http_decoy" && (
                      <>
                        <button
                          onClick={() => handleFireProbe("http_decoy", "/.env")}
                          disabled={isSimulating !== null}
                          style={{ fontSize: "10.5px", padding: "3px 8px", backgroundColor: "var(--color-surface-elevated)", border: "1px solid var(--color-border)", borderRadius: "var(--radius-sm)", color: "var(--color-accent-primary)", display: "flex", alignItems: "center", gap: "4px" }}
                        >
                          <Zap size={11} />
                          <span>Probe /.env</span>
                        </button>
                        <button
                          onClick={() => handleFireProbe("http_decoy", "/admin")}
                          disabled={isSimulating !== null}
                          style={{ fontSize: "10.5px", padding: "3px 8px", backgroundColor: "var(--color-surface-elevated)", border: "1px solid var(--color-border)", borderRadius: "var(--radius-sm)", color: "var(--color-accent-primary)", display: "flex", alignItems: "center", gap: "4px" }}
                        >
                          <Zap size={11} />
                          <span>Probe /admin</span>
                        </button>
                        <button
                          onClick={() => handleFireProbe("http_decoy", "/api/v1/internal")}
                          disabled={isSimulating !== null}
                          style={{ fontSize: "10.5px", padding: "3px 8px", backgroundColor: "var(--color-surface-elevated)", border: "1px solid var(--color-border)", borderRadius: "var(--radius-sm)", color: "var(--color-accent-primary)", display: "flex", alignItems: "center", gap: "4px" }}
                        >
                          <Zap size={11} />
                          <span>Probe /api</span>
                        </button>
                      </>
                    )}

                    {svc.service_type === "admin_portal" && (
                      <>
                        <button
                          onClick={() => handleFireProbe("admin_portal", "/admin/login")}
                          disabled={isSimulating !== null}
                          style={{ fontSize: "10.5px", padding: "3px 8px", backgroundColor: "var(--color-surface-elevated)", border: "1px solid var(--color-border)", borderRadius: "var(--radius-sm)", color: "var(--color-warning)", display: "flex", alignItems: "center", gap: "4px" }}
                        >
                          <Zap size={11} />
                          <span>Credential Spraying</span>
                        </button>
                        <button
                          onClick={() => handleFireProbe("admin_portal", "/oauth/authorize")}
                          disabled={isSimulating !== null}
                          style={{ fontSize: "10.5px", padding: "3px 8px", backgroundColor: "var(--color-surface-elevated)", border: "1px solid var(--color-border)", borderRadius: "var(--radius-sm)", color: "var(--color-warning)", display: "flex", alignItems: "center", gap: "4px" }}
                        >
                          <Zap size={11} />
                          <span>SSO Bypass Probe</span>
                        </button>
                      </>
                    )}

                    {svc.service_type === "ssh_banner" && (
                      <>
                        <button
                          onClick={() => handleFireProbe("ssh_banner")}
                          disabled={isSimulating !== null}
                          style={{ fontSize: "10.5px", padding: "3px 8px", backgroundColor: "var(--color-surface-elevated)", border: "1px solid var(--color-border)", borderRadius: "var(--radius-sm)", color: "var(--color-success)", display: "flex", alignItems: "center", gap: "4px" }}
                        >
                          <Zap size={11} />
                          <span>Test SSH Handshake</span>
                        </button>
                      </>
                    )}
                  </div>
                </div>
              </div>

              {/* Action Button */}
              <div style={{ marginTop: "4px" }}>
                {isRunning ? (
                  <button
                    onClick={() => onStopService(svc.service_type)}
                    style={{
                      width: "100%",
                      backgroundColor: "var(--color-critical)",
                      borderColor: "var(--color-critical)",
                      color: "#FFFFFF",
                      fontWeight: 600,
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      gap: "6px",
                    }}
                  >
                    <Square size={13} fill="#FFFFFF" />
                    <span>Stop Decoy</span>
                  </button>
                ) : (
                  <button
                    className="primary"
                    onClick={() => handleStartClicked(svc.service_type)}
                    style={{
                      width: "100%",
                      fontWeight: 600,
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      gap: "6px",
                    }}
                  >
                    <Play size={13} fill="#FFFFFF" />
                    <span>Start Decoy Service</span>
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Live Probe Execution Terminal Inspector (When simulation runs) */}
      {simulationResult && (
        <div
          style={{
            backgroundColor: "rgba(11, 17, 32, 0.95)",
            border: "1px solid var(--color-accent-primary)",
            borderRadius: "var(--radius-md)",
            padding: "14px 16px",
            boxShadow: "0 8px 24px rgba(0, 0, 0, 0.6), 0 0 12px rgba(56, 189, 248, 0.2)",
            position: "relative",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "10px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <ShieldAlert size={16} style={{ color: "var(--color-critical)" }} />
              <strong style={{ fontSize: "13px", color: "var(--color-text-primary)" }}>
                Live Honeypot Probe Captured & Evaluated
              </strong>
              <span
                style={{
                  fontSize: "10.5px",
                  padding: "1px 6px",
                  borderRadius: "10px",
                  backgroundColor: "rgba(52, 211, 153, 0.15)",
                  color: "var(--color-success)",
                  fontFamily: "var(--font-mono)",
                }}
              >
                ● Round-trip: {simulationResult.latency_ms} ms
              </span>
            </div>
            <button
              onClick={() => setSimulationResult(null)}
              style={{
                background: "transparent",
                border: "none",
                color: "var(--color-text-muted)",
                cursor: "pointer",
                padding: "2px",
              }}
              title="Close Inspector"
            >
              <X size={16} />
            </button>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", fontSize: "11px", fontFamily: "var(--font-mono)" }}>
            {/* Request */}
            <div style={{ backgroundColor: "#060A12", padding: "10px", borderRadius: "var(--radius-sm)", border: "1px solid var(--color-border-subtle)" }}>
              <div style={{ color: "var(--color-accent-primary)", fontWeight: 600, marginBottom: "4px" }}>
                → OUTGOING PROBE SENT ({simulationResult.target_address}):
              </div>
              <pre style={{ margin: 0, whiteSpace: "pre-wrap", color: "var(--color-text-primary)", maxHeight: "120px", overflowY: "auto" }}>
                {simulationResult.request_preview}
              </pre>
            </div>

            {/* Response */}
            <div style={{ backgroundColor: "#060A12", padding: "10px", borderRadius: "var(--radius-sm)", border: "1px solid var(--color-border-subtle)" }}>
              <div style={{ color: "var(--color-success)", fontWeight: 600, marginBottom: "4px" }}>
                ← DECOY SERVICE RESPONSE RECEIVED:
              </div>
              <pre style={{ margin: 0, whiteSpace: "pre-wrap", color: "var(--color-text-secondary)", maxHeight: "120px", overflowY: "auto" }}>
                {simulationResult.response_preview}
              </pre>
            </div>
          </div>

          <div style={{ marginTop: "10px", display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "11.5px", color: "var(--color-text-secondary)" }}>
            <span>
              🎯 <strong style={{ color: "var(--color-text-primary)" }}>Result:</strong> {simulationResult.message}
            </span>
            <span style={{ color: "var(--color-warning)", fontWeight: 600 }}>
              ⚡ Rule 8 Triggered • Event stored in SQLite
            </span>
          </div>
        </div>
      )}

      {/* Safe Testing Instructions Card with 1-Click Quick Action */}
      <div
        style={{
          padding: "14px 16px",
          backgroundColor: "var(--color-surface)",
          border: "1px solid var(--color-border)",
          borderRadius: "var(--radius-md)",
          fontSize: "12px",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
          <div style={{ fontWeight: 600, color: "var(--color-accent-primary)" }}>
            Authorized Security Testing Quick-Commands
          </div>
          <span style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>
            Click "Run Now" to test immediately from inside the app, or copy command for external terminal testing
          </span>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(310px, 1fr))", gap: "10px", fontFamily: "var(--font-mono)", fontSize: "11px" }}>
          {/* HTTP Decoy Test */}
          <div style={{ backgroundColor: "var(--color-bg)", padding: "10px", borderRadius: "var(--radius-sm)", border: "1px solid var(--color-border-subtle)", display: "flex", flexDirection: "column", justifyContent: "space-between", gap: "8px" }}>
            <div>
              <span style={{ color: "var(--color-text-muted)" }}># Test HTTP Recon Probe:</span>
              <div style={{ color: "var(--color-text-primary)", marginTop: "2px", fontWeight: 600 }}>curl http://127.0.0.1:8088/.env</div>
            </div>
            <div style={{ display: "flex", gap: "6px" }}>
              <button
                onClick={() => handleFireProbe("http_decoy", "/.env")}
                disabled={isSimulating !== null}
                style={{ flex: 1, padding: "4px 8px", fontSize: "10.5px", backgroundColor: "var(--color-accent-primary)", color: "var(--color-text-on-accent)", border: "none", borderRadius: "3px", fontWeight: 600, display: "flex", alignItems: "center", justifyContent: "center", gap: "4px" }}
              >
                {isSimulating === "http_decoy-/.env" ? <Loader2 size={12} className="spin" /> : <Zap size={12} />}
                <span>Run Probe Now</span>
              </button>
              <button
                onClick={() => handleCopyCommand("curl http://127.0.0.1:8088/.env", "cmd-http")}
                style={{ padding: "4px 8px", fontSize: "10.5px", display: "flex", alignItems: "center", gap: "4px" }}
                title="Copy Command"
              >
                {copiedId === "cmd-http" ? <Check size={12} style={{ color: "var(--color-success)" }} /> : <Copy size={12} />}
                <span>{copiedId === "cmd-http" ? "Copied" : "Copy"}</span>
              </button>
            </div>
          </div>

          {/* Admin Portal Test */}
          <div style={{ backgroundColor: "var(--color-bg)", padding: "10px", borderRadius: "var(--radius-sm)", border: "1px solid var(--color-border-subtle)", display: "flex", flexDirection: "column", justifyContent: "space-between", gap: "8px" }}>
            <div>
              <span style={{ color: "var(--color-text-muted)" }}># Test Admin Portal Probe:</span>
              <div style={{ color: "var(--color-text-primary)", marginTop: "2px", fontWeight: 600 }}>curl http://127.0.0.1:8443/admin</div>
            </div>
            <div style={{ display: "flex", gap: "6px" }}>
              <button
                onClick={() => handleFireProbe("admin_portal", "/admin")}
                disabled={isSimulating !== null}
                style={{ flex: 1, padding: "4px 8px", fontSize: "10.5px", backgroundColor: "var(--color-warning)", color: "#111827", border: "none", borderRadius: "3px", fontWeight: 600, display: "flex", alignItems: "center", justifyContent: "center", gap: "4px" }}
              >
                {isSimulating === "admin_portal-/admin" ? <Loader2 size={12} className="spin" /> : <Zap size={12} />}
                <span>Run Probe Now</span>
              </button>
              <button
                onClick={() => handleCopyCommand("curl http://127.0.0.1:8443/admin", "cmd-admin")}
                style={{ padding: "4px 8px", fontSize: "10.5px", display: "flex", alignItems: "center", gap: "4px" }}
                title="Copy Command"
              >
                {copiedId === "cmd-admin" ? <Check size={12} style={{ color: "var(--color-success)" }} /> : <Copy size={12} />}
                <span>{copiedId === "cmd-admin" ? "Copied" : "Copy"}</span>
              </button>
            </div>
          </div>

          {/* SSH Version Handshake */}
          <div style={{ backgroundColor: "var(--color-bg)", padding: "10px", borderRadius: "var(--radius-sm)", border: "1px solid var(--color-border-subtle)", display: "flex", flexDirection: "column", justifyContent: "space-between", gap: "8px" }}>
            <div>
              <span style={{ color: "var(--color-text-muted)" }}># Test SSH Version Handshake:</span>
              <div style={{ color: "var(--color-text-primary)", marginTop: "2px", fontWeight: 600 }}>ssh -p 2222 127.0.0.1</div>
            </div>
            <div style={{ display: "flex", gap: "6px" }}>
              <button
                onClick={() => handleFireProbe("ssh_banner")}
                disabled={isSimulating !== null}
                style={{ flex: 1, padding: "4px 8px", fontSize: "10.5px", backgroundColor: "var(--color-success)", color: "#061A12", border: "none", borderRadius: "3px", fontWeight: 600, display: "flex", alignItems: "center", justifyContent: "center", gap: "4px" }}
              >
                {isSimulating === "ssh_banner-default" ? <Loader2 size={12} className="spin" /> : <Zap size={12} />}
                <span>Run Probe Now</span>
              </button>
              <button
                onClick={() => handleCopyCommand("ssh -p 2222 127.0.0.1", "cmd-ssh")}
                style={{ padding: "4px 8px", fontSize: "10.5px", display: "flex", alignItems: "center", gap: "4px" }}
                title="Copy Command"
              >
                {copiedId === "cmd-ssh" ? <Check size={12} style={{ color: "var(--color-success)" }} /> : <Copy size={12} />}
                <span>{copiedId === "cmd-ssh" ? "Copied" : "Copy"}</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Honeypot Interaction Log Table */}
      <div style={{ display: "flex", flexDirection: "column", gap: "8px", flex: 1, minHeight: 0 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <h3 style={{ fontSize: "13px", fontWeight: 600, color: "var(--color-text-primary)" }}>
              Honeypot Interaction Log
            </h3>
            <p style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>
              Recorded probe attempts against local decoy ports
            </p>
          </div>
          <button className="ghost" onClick={onRefresh} style={{ fontSize: "11px" }}>
            Refresh Logs
          </button>
        </div>

        <div
          className="table-wrapper"
          tabIndex={0}
          role="region"
          aria-label="Honeypot probe activity table"
          style={{ flex: 1, minHeight: "160px" }}
        >
          <table>
            <thead>
              <tr>
                <th style={{ width: "90px" }}>Time</th>
                <th style={{ width: "110px" }}>Service</th>
                <th style={{ width: "150px" }}>Client Origin</th>
                <th>Probe Summary</th>
                <th>User-Agent / Signature</th>
                <th style={{ width: "95px" }}>Status</th>
              </tr>
            </thead>
            <tbody>
              {logs.length === 0 ? (
                <TableEmptyRow
                  colSpan={6}
                  title="Zero Decoy Probes Logged"
                  description="No connection attempts or unauthorized probes have touched the configured honeypot ports. Click 'Run Probe Now' above to test."
                  badgeText="Safe Loopback Decoy Traps Armed"
                  iconType="success"
                />
              ) : (
                logs.map((log) => (
                  <tr key={log.id}>
                    <td className="font-mono" style={{ color: "var(--color-text-muted)", fontSize: "11px" }}>
                      {formatDateTime(log.timestamp).split(", ")[1] || log.timestamp.substring(11, 19)}
                    </td>
                    <td style={{ fontWeight: 600, color: "var(--color-text-primary)" }}>
                      {log.service_type === "http_decoy" ? "HTTP Decoy" : log.service_type === "admin_portal" ? "Admin Portal" : "SSH Banner"}
                    </td>
                    <td className="font-mono">
                      {log.client_ip}:{log.client_port}
                    </td>
                    <td style={{ maxWidth: "280px", overflow: "hidden", textOverflow: "ellipsis" }}>
                      {log.probe_summary}
                    </td>
                    <td className="font-mono" style={{ color: "var(--color-text-muted)", fontSize: "11px", maxWidth: "200px", overflow: "hidden", textOverflow: "ellipsis" }}>
                      {log.user_agent || log.payload_preview_sanitized || "—"}
                    </td>
                    <td>
                      {log.flagged_as_suspicious ? (
                        <span className="badge" style={{ backgroundColor: "#2A1215", borderColor: "var(--color-critical)", color: "var(--color-critical)" }}>
                          Suspicious
                        </span>
                      ) : (
                        <span className="badge" style={{ backgroundColor: "#10261E", borderColor: "var(--color-success)", color: "var(--color-success)" }}>
                          Logged
                        </span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Confirmation Dialog for LAN Exposure */}
      <ConfirmationDialog
        isOpen={Boolean(pendingLanService)}
        title="Expose Honeypot Decoy to Local Network (LAN)?"
        description={`You are about to bind ${pendingLanService?.serviceType} to 0.0.0.0 on port ${pendingLanService?.port}. Other devices on your local network will be able to connect to this decoy service. Ensure you have authorization on this network and understand that Windows Firewall may require approval.`}
        confirmLabel="Confirm LAN Exposure"
        cancelLabel="Cancel"
        isDestructive={false}
        onConfirm={handleConfirmLanExposure}
        onCancel={() => setPendingLanService(null)}
      />
    </div>
  );
};
