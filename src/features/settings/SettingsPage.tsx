import React, { useState } from "react";
import { AppSettings } from "../../types/settings";
import { DriverStatus, NetworkInterfaceInfo } from "../../types/network";
import { ConfirmationDialog } from "../../components/ConfirmationDialog";
import {
  Sliders,
  Shield,
  FlaskConical,
  Database,
  Info,
  CheckCircle2,
  AlertTriangle,
  Play,
  RotateCcw,
  Trash2,
  HardDrive,
  Save,
  Volume2,
  VolumeX,
  Palette,
} from "lucide-react";
import { soundEffects } from "../../lib/soundEffects";

interface SettingsPageProps {
  settings: AppSettings;
  driverStatus: DriverStatus;
  interfaces: NetworkInterfaceInfo[];
  onSaveSettings: (settings: AppSettings) => Promise<void>;
  onPurgeDatabase: (retentionDays?: number) => void;
  onRunLabScenario: (scenarioName: string) => Promise<{ success: boolean; message: string }>;
}

export const SettingsPage: React.FC<SettingsPageProps> = ({
  settings,
  driverStatus,
  interfaces,
  onSaveSettings,
  onPurgeDatabase,
  onRunLabScenario,
}) => {
  const [currentSettings, setCurrentSettings] = useState<AppSettings>(settings);
  const [activeSection, setActiveSection] = useState<"network" | "detection" | "honeypot" | "privacy" | "diagnostics" | "audio" | "themes">("network");
  const [isPurgeModalOpen, setIsPurgeModalOpen] = useState(false);
  const [labMessage, setLabMessage] = useState<string | null>(null);
  const [isSavedNotice, setIsSavedNotice] = useState(false);
  const [isMuted, setIsMuted] = useState(soundEffects.isMuted());
  const [activeTheme, setActiveTheme] = useState(() => localStorage.getItem("shadowsentry_theme") || "nordic-slate");

  const handleSave = async () => {
    await onSaveSettings(currentSettings);
    setIsSavedNotice(true);
    setTimeout(() => setIsSavedNotice(false), 2500);
  };

  const handleRunScenario = async (name: string) => {
    setLabMessage("Executing laboratory test case...");
    const res = await onRunLabScenario(name);
    setLabMessage(res.message);
    setTimeout(() => setLabMessage(null), 4000);
  };

  return (
    <div style={{ display: "flex", height: "100%", width: "100%", overflow: "hidden" }}>
      {/* Left Settings Navigation Sub-menu */}
      <div
        style={{
          width: "200px",
          backgroundColor: "var(--color-surface)",
          borderRight: "1px solid var(--color-border)",
          display: "flex",
          flexDirection: "column",
          padding: "16px 8px",
          gap: "4px",
          flexShrink: 0,
        }}
      >
        <div style={{ fontSize: "11px", fontWeight: 700, color: "var(--color-text-muted)", textTransform: "uppercase", padding: "0 8px 8px" }}>
          Settings Navigation
        </div>

        {[
          { id: "network", label: "Network Capture", icon: HardDrive },
          { id: "detection", label: "Detection Rules", icon: Shield },
          { id: "honeypot", label: "Honeypot Lab", icon: FlaskConical },
          { id: "privacy", label: "Privacy & Storage", icon: Database },
          { id: "diagnostics", label: "Lab & Diagnostics", icon: Info },
          { id: "audio", label: "Sound & Alerts", icon: Volume2 },
          { id: "themes", label: "Cyber Themes", icon: Palette },
        ].map((sec) => {
          const Icon = sec.icon;
          const active = activeSection === sec.id;
          return (
            <button
              key={sec.id}
              onClick={() => setActiveSection(sec.id as any)}
              style={{
                width: "100%",
                padding: "8px 10px",
                display: "flex",
                alignItems: "center",
                gap: "8px",
                backgroundColor: active ? "var(--color-surface-elevated)" : "transparent",
                borderColor: active ? "var(--color-border)" : "transparent",
                borderLeft: active ? "3px solid var(--color-accent-primary)" : "3px solid transparent",
                color: active ? "var(--color-text-primary)" : "var(--color-text-secondary)",
                fontWeight: active ? 600 : 400,
                textAlign: "left",
                borderRadius: "var(--radius-sm)",
              }}
            >
              <Icon size={14} style={{ color: active ? "var(--color-accent-primary)" : "var(--color-text-muted)" }} />
              <span style={{ fontSize: "12px" }}>{sec.label}</span>
            </button>
          );
        })}
      </div>

      {/* Main Settings Form Column */}
      <div style={{ flex: 1, padding: "20px 24px", overflowY: "auto", display: "flex", flexDirection: "column", gap: "20px" }}>
        
        {/* Top Title and Save Button */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", borderBottom: "1px solid var(--color-border)", paddingBottom: "14px" }}>
          <div>
            <h2 style={{ fontSize: "16px", fontWeight: 700, color: "var(--color-text-primary)" }}>
              {activeSection === "network" && "Network Monitoring Configuration"}
              {activeSection === "detection" && "Threat Detection Rules & Heuristic Thresholds"}
              {activeSection === "honeypot" && "Honeypot Laboratory Limits & Ports"}
              {activeSection === "privacy" && "Privacy Controls & SQLite Local Data Retention"}
              {activeSection === "diagnostics" && "Windows Diagnostics & Lab Testing Controls"}
            </h2>
            <div style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>
              Customize desktop security heuristics, storage boundaries, and hardware backends
            </div>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            {isSavedNotice && (
              <span style={{ fontSize: "12px", color: "var(--color-success)", display: "flex", alignItems: "center", gap: "4px" }}>
                <CheckCircle2 size={14} /> Saved
              </span>
            )}
            <button className="primary" onClick={handleSave} style={{ fontWeight: 600 }}>
              <Save size={13} />
              <span>Save Configuration</span>
            </button>
          </div>
        </div>

        {/* SECTION 1: NETWORK MONITORING */}
        {activeSection === "network" && (
          <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
            <div style={{ backgroundColor: "var(--color-surface)", padding: "16px", borderRadius: "var(--radius-md)", border: "1px solid var(--color-border)" }}>
              <h3 style={{ fontSize: "13px", fontWeight: 600, color: "var(--color-text-primary)", marginBottom: "12px" }}>
                Packet Capture Engine & Interface Selection
              </h3>

              <div style={{ display: "flex", flexDirection: "column", gap: "14px", fontSize: "12px" }}>
                <div>
                  <label htmlFor="settings-preferred-iface" style={{ color: "var(--color-text-secondary)", display: "block", marginBottom: "4px" }}>
                    Preferred Monitoring Interface:
                  </label>
                  <select
                    id="settings-preferred-iface"
                    value={currentSettings.preferred_interface || ""}
                    onChange={(e) => setCurrentSettings({ ...currentSettings, preferred_interface: e.target.value })}
                    style={{ width: "100%", maxWidth: "400px" }}
                  >
                    <option value="">Auto-detect default active adapter</option>
                    {interfaces.map((i) => (
                      <option key={i.id} value={i.friendly_name}>
                        {i.friendly_name} ({i.ipv4_addresses[0] || "No IP"})
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label htmlFor="settings-preferred-backend" style={{ color: "var(--color-text-secondary)", display: "block", marginBottom: "4px" }}>
                    Preferred Packet Capture Backend:
                  </label>
                  <select
                    id="settings-preferred-backend"
                    value={currentSettings.preferred_backend}
                    onChange={(e) => setCurrentSettings({ ...currentSettings, preferred_backend: e.target.value as any })}
                    style={{ width: "100%", maxWidth: "400px" }}
                  >
                    <option value="npcap">Npcap (Layer 2 Promiscuous Ethernet)</option>
                    <option value="raw_socket">Windows Native Raw Sockets (Administrator)</option>
                    <option value="iphelper">Windows IP Helper Flow Monitor</option>
                    <option value="lab_synthetic">Laboratory Synthetic Mode</option>
                  </select>
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginTop: "4px" }}>
                  <input
                    type="checkbox"
                    id="metadata-only"
                    checked={!currentSettings.privacy.payload_capture_enabled}
                    onChange={(e) =>
                      setCurrentSettings({
                        ...currentSettings,
                        privacy: { ...currentSettings.privacy, payload_capture_enabled: !e.target.checked },
                      })
                    }
                  />
                  <label htmlFor="metadata-only" style={{ color: "var(--color-text-primary)" }}>
                    Metadata-Only Capture Mode (Recommended — raw application payloads discarded)
                  </label>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* SECTION 2: DETECTION RULES & THRESHOLDS */}
        {activeSection === "detection" && (
          <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
            <div style={{ backgroundColor: "var(--color-surface)", padding: "16px", borderRadius: "var(--radius-md)", border: "1px solid var(--color-border)" }}>
              <h3 style={{ fontSize: "13px", fontWeight: 600, color: "var(--color-text-primary)", marginBottom: "12px" }}>
                Heuristic Detection Thresholds
              </h3>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", fontSize: "12px" }}>
                <div>
                  <label htmlFor="th-port-scan-count" style={{ color: "var(--color-text-secondary)", display: "block", marginBottom: "4px" }}>
                    Port Scan: Distinct Ports Threshold
                  </label>
                  <input
                    id="th-port-scan-count"
                    type="number"
                    value={currentSettings.thresholds.port_scan_count}
                    onChange={(e) =>
                      setCurrentSettings({
                        ...currentSettings,
                        thresholds: { ...currentSettings.thresholds, port_scan_count: parseInt(e.target.value) || 1 },
                      })
                    }
                    style={{ width: "120px", fontFamily: "var(--font-mono)" }}
                  />
                  <div style={{ fontSize: "11px", color: "var(--color-text-muted)", marginTop: "2px" }}>Trigger if &ge; N ports hit</div>
                </div>

                <div>
                  <label htmlFor="th-port-scan-window" style={{ color: "var(--color-text-secondary)", display: "block", marginBottom: "4px" }}>
                    Port Scan: Time Window (seconds)
                  </label>
                  <input
                    id="th-port-scan-window"
                    type="number"
                    value={currentSettings.thresholds.port_scan_window_secs}
                    onChange={(e) =>
                      setCurrentSettings({
                        ...currentSettings,
                        thresholds: { ...currentSettings.thresholds, port_scan_window_secs: parseInt(e.target.value) || 1 },
                      })
                    }
                    style={{ width: "120px", fontFamily: "var(--font-mono)" }}
                  />
                </div>

                <div>
                  <label htmlFor="th-burst-rate" style={{ color: "var(--color-text-secondary)", display: "block", marginBottom: "4px" }}>
                    Traffic Burst Threshold (packets)
                  </label>
                  <input
                    id="th-burst-rate"
                    type="number"
                    value={currentSettings.thresholds.burst_packet_rate}
                    onChange={(e) =>
                      setCurrentSettings({
                        ...currentSettings,
                        thresholds: { ...currentSettings.thresholds, burst_packet_rate: parseInt(e.target.value) || 100 },
                      })
                    }
                    style={{ width: "120px", fontFamily: "var(--font-mono)" }}
                  />
                </div>

                <div>
                  <label htmlFor="th-burst-window" style={{ color: "var(--color-text-secondary)", display: "block", marginBottom: "4px" }}>
                    Traffic Burst Window (seconds)
                  </label>
                  <input
                    id="th-burst-window"
                    type="number"
                    value={currentSettings.thresholds.burst_window_secs}
                    onChange={(e) =>
                      setCurrentSettings({
                        ...currentSettings,
                        thresholds: { ...currentSettings.thresholds, burst_window_secs: parseInt(e.target.value) || 1 },
                      })
                    }
                    style={{ width: "120px", fontFamily: "var(--font-mono)" }}
                  />
                </div>

                <div>
                  <label htmlFor="th-dns-entropy" style={{ color: "var(--color-text-secondary)", display: "block", marginBottom: "4px" }}>
                    DNS Shannon Entropy Score Threshold
                  </label>
                  <input
                    id="th-dns-entropy"
                    type="number"
                    step="0.1"
                    value={currentSettings.thresholds.dns_entropy_min}
                    onChange={(e) =>
                      setCurrentSettings({
                        ...currentSettings,
                        thresholds: { ...currentSettings.thresholds, dns_entropy_min: parseFloat(e.target.value) || 3.0 },
                      })
                    }
                    style={{ width: "120px", fontFamily: "var(--font-mono)" }}
                  />
                  <div style={{ fontSize: "11px", color: "var(--color-text-muted)", marginTop: "2px" }}>Higher score = more random (DGA indicator)</div>
                </div>

                <div>
                  <label htmlFor="th-dns-max-len" style={{ color: "var(--color-text-secondary)", display: "block", marginBottom: "4px" }}>
                    Suspicious DNS Name Max Length
                  </label>
                  <input
                    id="th-dns-max-len"
                    type="number"
                    value={currentSettings.thresholds.dns_max_name_length}
                    onChange={(e) =>
                      setCurrentSettings({
                        ...currentSettings,
                        thresholds: { ...currentSettings.thresholds, dns_max_name_length: parseInt(e.target.value) || 50 },
                      })
                    }
                    style={{ width: "120px", fontFamily: "var(--font-mono)" }}
                  />
                  <div style={{ fontSize: "11px", color: "var(--color-text-muted)", marginTop: "2px" }}>Flag domains exceeding N characters</div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* SECTION 3: HONEYPOT LAB SETTINGS */}
        {activeSection === "honeypot" && (
          <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
            <div style={{ backgroundColor: "var(--color-surface)", padding: "16px", borderRadius: "var(--radius-md)", border: "1px solid var(--color-border)" }}>
              <h3 style={{ fontSize: "13px", fontWeight: 600, color: "var(--color-text-primary)", marginBottom: "12px" }}>
                Honeypot Decoy Limits and Bounded Sockets
              </h3>

              <div style={{ display: "flex", flexDirection: "column", gap: "12px", fontSize: "12px" }}>
                <div style={{ padding: "10px", backgroundColor: "var(--color-bg)", borderRadius: "var(--radius-sm)", border: "1px solid var(--color-border-subtle)" }}>
                  <div style={{ fontWeight: 600, color: "var(--color-text-primary)" }}>Safety & Reachability Policy</div>
                  <div style={{ color: "var(--color-text-muted)", fontSize: "11px", marginTop: "2px" }}>
                    All decoy services default to loopback <code>127.0.0.1</code> only. If LAN exposure (<code>0.0.0.0</code>)
                    is enabled, an explicit confirmation dialog is always required to prevent unintended exposure to the local network.
                  </div>
                </div>

                <div style={{ padding: "10px", backgroundColor: "var(--color-bg)", borderRadius: "var(--radius-sm)", border: "1px solid var(--color-border-subtle)" }}>
                  <div style={{ fontWeight: 600, color: "var(--color-text-primary)" }}>Resource Limits & Timeouts</div>
                  <div style={{ color: "var(--color-text-muted)", fontSize: "11px", marginTop: "2px" }}>
                    All incoming honeypot connections are subject to a strict 10-second timeout, request size ceiling of 8KB,
                    and connection rate limits. Client input is never executed in a shell or subprocess.
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* SECTION 4: PRIVACY & RETENTION */}
        {activeSection === "privacy" && (
          <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
            <div style={{ backgroundColor: "var(--color-surface)", padding: "16px", borderRadius: "var(--radius-md)", border: "1px solid var(--color-border)" }}>
              <h3 style={{ fontSize: "13px", fontWeight: 600, color: "var(--color-text-primary)", marginBottom: "12px" }}>
                Local Data Storage & Privacy Boundaries
              </h3>

              <div style={{ display: "flex", flexDirection: "column", gap: "14px", fontSize: "12px" }}>
                <div>
                  <label htmlFor="settings-retention" style={{ color: "var(--color-text-secondary)", display: "block", marginBottom: "4px" }}>
                    Event Storage Retention Period:
                  </label>
                  <select
                    id="settings-retention"
                    value={currentSettings.privacy.retention_days}
                    onChange={(e) =>
                      setCurrentSettings({
                        ...currentSettings,
                        privacy: { ...currentSettings.privacy, retention_days: parseInt(e.target.value) || 14 },
                      })
                    }
                    style={{ width: "200px" }}
                  >
                    <option value={7}>7 Days</option>
                    <option value={14}>14 Days (Default)</option>
                    <option value={30}>30 Days</option>
                    <option value={90}>90 Days</option>
                    <option value={0}>Indefinite (Manual Purge Only)</option>
                  </select>
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <input
                    type="checkbox"
                    id="redact-ips"
                    checked={currentSettings.privacy.redact_sensitive_local_ips}
                    onChange={(e) =>
                      setCurrentSettings({
                        ...currentSettings,
                        privacy: { ...currentSettings.privacy, redact_sensitive_local_ips: e.target.checked },
                      })
                    }
                  />
                  <label htmlFor="redact-ips" style={{ color: "var(--color-text-primary)" }}>
                    Redact sensitive local host IPs in CSV and JSON exports (e.g. 192.168.1.xxx)
                  </label>
                </div>

                <div style={{ borderTop: "1px solid var(--color-border-subtle)", paddingTop: "14px" }}>
                  <div style={{ fontWeight: 600, color: "var(--color-critical)", marginBottom: "4px" }}>
                    User-Controlled Database Purge
                  </div>
                  <p style={{ color: "var(--color-text-muted)", fontSize: "11px", marginBottom: "10px" }}>
                    Permanently delete all stored events, DNS history, and honeypot records from the local SQLite database.
                  </p>
                  <button
                    onClick={() => setIsPurgeModalOpen(true)}
                    style={{ backgroundColor: "#2A1215", borderColor: "var(--color-critical)", color: "var(--color-critical)" }}
                  >
                    <Trash2 size={13} />
                    <span>Purge Stored Database Records</span>
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* SECTION 5: DIAGNOSTICS & LAB TESTING */}
        {activeSection === "diagnostics" && (
          <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
            <div style={{ backgroundColor: "var(--color-surface)", padding: "16px", borderRadius: "var(--radius-md)", border: "1px solid var(--color-border)" }}>
              <h3 style={{ fontSize: "13px", fontWeight: 600, color: "var(--color-text-primary)", marginBottom: "12px" }}>
                Windows Host Diagnostics & Elevation Status
              </h3>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px", fontSize: "12px", marginBottom: "16px" }}>
                <div style={{ padding: "10px", backgroundColor: "var(--color-bg)", borderRadius: "var(--radius-sm)", border: "1px solid var(--color-border-subtle)" }}>
                  <div style={{ color: "var(--color-text-muted)", fontSize: "10px", textTransform: "uppercase" }}>Windows Elevation Level</div>
                  <div style={{ fontWeight: 600, color: driverStatus.is_elevated_admin ? "var(--color-success)" : "var(--color-warning)", marginTop: "2px" }}>
                    {driverStatus.is_elevated_admin ? "Elevated Administrator Token" : "Standard User Privilege"}
                  </div>
                </div>

                <div style={{ padding: "10px", backgroundColor: "var(--color-bg)", borderRadius: "var(--radius-sm)", border: "1px solid var(--color-border-subtle)" }}>
                  <div style={{ color: "var(--color-text-muted)", fontSize: "10px", textTransform: "uppercase" }}>Npcap Driver Status</div>
                  <div style={{ fontWeight: 600, color: driverStatus.npcap_installed ? "var(--color-success)" : "var(--color-text-secondary)", marginTop: "2px" }}>
                    {driverStatus.npcap_installed ? "Installed & Service Active" : "Not Installed (Optional)"}
                  </div>
                </div>
              </div>

              {/* Lab Test Scenario Triggers */}
              <div style={{ borderTop: "1px solid var(--color-border-subtle)", paddingTop: "14px" }}>
                <div style={{ fontWeight: 600, color: "var(--color-accent-primary)", marginBottom: "6px" }}>
                  Authorized Security Laboratory Scenario Injection
                </div>
                <p style={{ color: "var(--color-text-muted)", fontSize: "11px", marginBottom: "12px" }}>
                  Trigger verified test cases in the local security engine to confirm detection rule logic and forensic explanations:
                </p>

                {labMessage && (
                  <div style={{ padding: "8px 12px", backgroundColor: "#10261E", border: "1px solid var(--color-success)", borderRadius: "var(--radius-sm)", color: "var(--color-success)", fontSize: "11px", marginBottom: "12px" }}>
                    {labMessage}
                  </div>
                )}

                <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
                  <button onClick={() => handleRunScenario("port_scan")}>
                    <Play size={12} />
                    <span>Inject Port Sweep Test Case (Rule 1)</span>
                  </button>
                  <button onClick={() => handleRunScenario("suspicious_dns")}>
                    <Play size={12} />
                    <span>Inject DGA Query Test Case (Rule 4)</span>
                  </button>
                  <button onClick={() => handleRunScenario("arp_anomaly")}>
                    <Play size={12} />
                    <span>Inject ARP Mapping Conflict (Rule 6)</span>
                  </button>
                  <button onClick={() => handleRunScenario("threat_intel")}>
                    <Play size={12} />
                    <span>Inject Threat Intel IP Match (Rule 7)</span>
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Section 6: Sound & Alerts */}
        {activeSection === "audio" && (
          <div style={{ display: "flex", flexDirection: "column", gap: "20px", maxWidth: "800px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
              <div>
                <h2 style={{ fontSize: "16px", fontWeight: 700, margin: 0, color: "var(--color-text-primary)" }}>
                  Tactical SOC Audio & Sound Effects
                </h2>
                <p style={{ fontSize: "12px", color: "var(--color-text-muted)", margin: "4px 0 0" }}>
                  Configure real-time audio cues for packet sniffer status, threat alerts, and diagnostic checks.
                </p>
              </div>
            </div>

            {/* Master Audio Control Card */}
            <div className="card" style={{ padding: "16px", display: "flex", flexDirection: "column", gap: "14px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div>
                  <div style={{ fontSize: "13px", fontWeight: 600, color: "var(--color-text-primary)" }}>
                    Master Audio State
                  </div>
                  <div style={{ fontSize: "12px", color: "var(--color-text-muted)", marginTop: "2px" }}>
                    Synthesized natively via standard Web Audio API. Zero external audio downloads.
                  </div>
                </div>
                <button
                  className={isMuted ? "ghost" : "primary"}
                  onClick={() => {
                    const newMuted = soundEffects.toggleMute();
                    setIsMuted(newMuted);
                    if (!newMuted) {
                      soundEffects.playToggle();
                    }
                  }}
                  style={{ display: "flex", alignItems: "center", gap: "6px" }}
                >
                  {isMuted ? <VolumeX size={15} /> : <Volume2 size={15} />}
                  <span>{isMuted ? "Muted (Click to Enable)" : "Audio Active (Click to Mute)"}</span>
                </button>
              </div>
            </div>

            {/* Audio Testing Board */}
            <div className="card" style={{ padding: "16px", display: "flex", flexDirection: "column", gap: "12px" }}>
              <div style={{ fontSize: "13px", fontWeight: 600, color: "var(--color-text-primary)" }}>
                Tactical Audio Test Board
              </div>
              <div style={{ fontSize: "12px", color: "var(--color-text-muted)" }}>
                Sample each synthesized sound to preview volume levels and frequency characteristics:
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "10px", marginTop: "6px" }}>
                <div style={{ padding: "10px", border: "1px solid var(--color-border)", borderRadius: "var(--radius-sm)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <div>
                    <div style={{ fontSize: "12px", fontWeight: 600 }}>Boot Chime</div>
                    <div style={{ fontSize: "10px", color: "var(--color-text-muted)" }}>Startup Tri-Tone Sweep</div>
                  </div>
                  <button className="ghost" onClick={() => soundEffects.playBootChime()} style={{ padding: "4px 8px", fontSize: "11px" }}>
                    <Play size={11} /> Play
                  </button>
                </div>

                <div style={{ padding: "10px", border: "1px solid var(--color-border)", borderRadius: "var(--radius-sm)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <div>
                    <div style={{ fontSize: "12px", fontWeight: 600 }}>Diagnostic Tick</div>
                    <div style={{ fontSize: "10px", color: "var(--color-text-muted)" }}>Subsystem Check Blip</div>
                  </div>
                  <button className="ghost" onClick={() => soundEffects.playDiagnosticTick()} style={{ padding: "4px 8px", fontSize: "11px" }}>
                    <Play size={11} /> Play
                  </button>
                </div>

                <div style={{ padding: "10px", border: "1px solid var(--color-border)", borderRadius: "var(--radius-sm)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <div>
                    <div style={{ fontSize: "12px", fontWeight: 600, color: "var(--color-critical)" }}>Critical Alert</div>
                    <div style={{ fontSize: "10px", color: "var(--color-text-muted)" }}>Dual-Pulse Threat Ping</div>
                  </div>
                  <button className="ghost" onClick={() => soundEffects.playThreatAlert("critical")} style={{ padding: "4px 8px", fontSize: "11px", color: "var(--color-critical)" }}>
                    <Play size={11} /> Play
                  </button>
                </div>

                <div style={{ padding: "10px", border: "1px solid var(--color-border)", borderRadius: "var(--radius-sm)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <div>
                    <div style={{ fontSize: "12px", fontWeight: 600, color: "var(--color-warning)" }}>Medium Alert</div>
                    <div style={{ fontSize: "10px", color: "var(--color-text-muted)" }}>Sonar Anomaly Chime</div>
                  </div>
                  <button className="ghost" onClick={() => soundEffects.playThreatAlert("medium")} style={{ padding: "4px 8px", fontSize: "11px", color: "var(--color-warning)" }}>
                    <Play size={11} /> Play
                  </button>
                </div>

                <div style={{ padding: "10px", border: "1px solid var(--color-border)", borderRadius: "var(--radius-sm)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <div>
                    <div style={{ fontSize: "12px", fontWeight: 600, color: "var(--color-accent-secondary)" }}>Honeypot Trigger</div>
                    <div style={{ fontSize: "10px", color: "var(--color-text-muted)" }}>Intrusion Radar Sweep</div>
                  </div>
                  <button className="ghost" onClick={() => soundEffects.playHoneypotTrigger()} style={{ padding: "4px 8px", fontSize: "11px", color: "var(--color-accent-secondary)" }}>
                    <Play size={11} /> Play
                  </button>
                </div>

                <div style={{ padding: "10px", border: "1px solid var(--color-border)", borderRadius: "var(--radius-sm)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <div>
                    <div style={{ fontSize: "12px", fontWeight: 600 }}>Sniffer Start / Stop</div>
                    <div style={{ fontSize: "10px", color: "var(--color-text-muted)" }}>Capture State Transition</div>
                  </div>
                  <div style={{ display: "flex", gap: "4px" }}>
                    <button className="ghost" onClick={() => soundEffects.playMonitoringStart()} style={{ padding: "4px 6px", fontSize: "10px" }}>Start</button>
                    <button className="ghost" onClick={() => soundEffects.playMonitoringStop()} style={{ padding: "4px 6px", fontSize: "10px" }}>Stop</button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Section 7: Cyber Themes */}
        {activeSection === "themes" && (
          <div style={{ display: "flex", flexDirection: "column", gap: "20px", maxWidth: "800px" }}>
            <div>
              <h2 style={{ fontSize: "16px", fontWeight: 700, margin: 0, color: "var(--color-text-primary)" }}>
                Cyber Console Theme Studio
              </h2>
              <p style={{ fontSize: "12px", color: "var(--color-text-muted)", margin: "4px 0 0" }}>
                Switch between high-contrast, security operations console color schemes.
              </p>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: "14px" }}>
              {[
                {
                  id: "nordic-slate",
                  name: "Nordic Slate",
                  tagline: "Default Tactical SOC Console",
                  bg: "#0B1120",
                  surface: "#1E293B",
                  accent: "#38BDF8",
                  accentSecondary: "#2DD4BF",
                  border: "#334155",
                  description: "Tailored deep navy slate with cyan and teal telemetry accents for long surveillance shifts.",
                },
                {
                  id: "cyberpunk-emerald",
                  name: "Cyberpunk Emerald",
                  tagline: "Matrix OLED Terminal",
                  bg: "#030A06",
                  surface: "#0B2216",
                  accent: "#10B981",
                  accentSecondary: "#34D399",
                  border: "#1E4631",
                  description: "High-contrast true black background with vibrant radar green phosphor accents.",
                },
                {
                  id: "midnight-cobalt",
                  name: "Midnight Cobalt",
                  tagline: "Deep Ocean SOC Console",
                  bg: "#060914",
                  surface: "#121B38",
                  accent: "#3B82F6",
                  accentSecondary: "#60A5FA",
                  border: "#25396B",
                  description: "Professional enterprise SIEM aesthetics with electric cobalt blue telemetry elements.",
                },
                {
                  id: "crimson-lockdown",
                  name: "Crimson Lockdown",
                  tagline: "Red Team Incident Drill",
                  bg: "#0D0407",
                  surface: "#260C16",
                  accent: "#F43F5E",
                  accentSecondary: "#FB7185",
                  border: "#4D1A2C",
                  description: "High-alert tactical obsidian and signal red for active incident response drills.",
                },
              ].map((theme) => {
                const isCurrent = activeTheme === theme.id;
                return (
                  <div
                    key={theme.id}
                    onClick={() => {
                      setActiveTheme(theme.id);
                      localStorage.setItem("shadowsentry_theme", theme.id);
                      document.documentElement.setAttribute("data-theme", theme.id);
                      soundEffects.playToggle();
                    }}
                    style={{
                      padding: "16px",
                      borderRadius: "var(--radius-md)",
                      backgroundColor: theme.surface,
                      border: `2px solid ${isCurrent ? theme.accent : "var(--color-border)"}`,
                      boxShadow: isCurrent ? `0 0 16px ${theme.accent}33` : "none",
                      cursor: "pointer",
                      display: "flex",
                      flexDirection: "column",
                      gap: "10px",
                      transition: "all 0.18s ease",
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <div>
                        <div style={{ fontSize: "14px", fontWeight: 700, color: "#FFFFFF" }}>{theme.name}</div>
                        <div style={{ fontSize: "11px", color: theme.accent, fontWeight: 500 }}>{theme.tagline}</div>
                      </div>
                      {isCurrent && (
                        <span
                          style={{
                            fontSize: "10px",
                            fontWeight: 700,
                            padding: "2px 8px",
                            borderRadius: "10px",
                            backgroundColor: theme.accent,
                            color: "#000000",
                          }}
                        >
                          ACTIVE
                        </span>
                      )}
                    </div>

                    <div style={{ fontSize: "11.5px", color: "#CBD5E1", lineHeight: 1.4 }}>
                      {theme.description}
                    </div>

                    {/* Color Swatch Preview Bar */}
                    <div style={{ display: "flex", gap: "6px", alignItems: "center", marginTop: "4px" }}>
                      <span style={{ fontSize: "10px", color: "#94A3B8" }}>Palette:</span>
                      <div style={{ width: "16px", height: "16px", borderRadius: "3px", backgroundColor: theme.bg, border: "1px solid #475569" }} title="Background" />
                      <div style={{ width: "16px", height: "16px", borderRadius: "3px", backgroundColor: theme.surface, border: "1px solid #475569" }} title="Surface" />
                      <div style={{ width: "16px", height: "16px", borderRadius: "3px", backgroundColor: theme.accent }} title="Primary Accent" />
                      <div style={{ width: "16px", height: "16px", borderRadius: "3px", backgroundColor: theme.accentSecondary }} title="Secondary Accent" />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

      </div>

      {/* Confirmation Dialog for Purging Database */}
      <ConfirmationDialog
        isOpen={isPurgeModalOpen}
        title="Permanently Purge Local Security Records?"
        description="All recorded security events, honeypot probe logs, and historical monitoring metrics will be deleted from your local SQLite database. This operation cannot be reversed."
        confirmLabel="Purge All Records"
        cancelLabel="Cancel"
        isDestructive={true}
        onConfirm={() => {
          onPurgeDatabase();
          setIsPurgeModalOpen(false);
        }}
        onCancel={() => setIsPurgeModalOpen(false)}
      />
    </div>
  );
};
