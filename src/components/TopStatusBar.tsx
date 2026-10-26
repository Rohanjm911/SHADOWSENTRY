import React, { useState } from "react";
import {
  Play,
  Square,
  Search,
  Wifi,
  HardDrive,
  Sliders,
  CheckCircle2,
  AlertCircle,
  Maximize2,
  Minimize2,
  Volume2,
  VolumeX,
  Palette,
  HelpCircle,
} from "lucide-react";
import { CaptureBackendType, NetworkInterfaceInfo } from "../types/network";

interface TopStatusBarProps {
  isMonitoring: boolean;
  activeBackend: CaptureBackendType | null;
  selectedInterface: string | null;
  interfaces: NetworkInterfaceInfo[];
  onSelectInterface: (ifaceName: string) => void;
  onStartMonitoring: () => void;
  onStopMonitoring: () => void;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  onOpenSettings: () => void;
  isCompact?: boolean;
  onToggleDensity?: () => void;
  isMuted?: boolean;
  onToggleMute?: () => void;
  currentTheme?: string;
  onSelectTheme?: (theme: string) => void;
  onOpenTutorial?: () => void;
}

export const TopStatusBar: React.FC<TopStatusBarProps> = ({
  isMonitoring,
  activeBackend,
  selectedInterface,
  interfaces,
  onSelectInterface,
  onStartMonitoring,
  onStopMonitoring,
  searchQuery,
  onSearchChange,
  onOpenSettings,
  isCompact = false,
  onToggleDensity,
  isMuted = false,
  onToggleMute,
  currentTheme = "nordic-slate",
  onSelectTheme,
  onOpenTutorial,
}) => {
  const [isThemeDropdownOpen, setIsThemeDropdownOpen] = useState(false);
  const formatBackendName = (b: CaptureBackendType | null) => {
    switch (b) {
      case "npcap":
        return "Npcap (L2 Promiscuous)";
      case "raw_socket":
        return "Windows Raw Socket (Admin)";
      case "iphelper":
        return "Windows IP Helper";
      case "lab_synthetic":
        return "Laboratory Mode";
      default:
        return "Backend Standby";
    }
  };

  return (
    <header
      style={{
        height: "var(--topbar-height)",
        backgroundColor: "var(--color-surface)",
        borderBottom: "1px solid var(--color-border)",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "0 16px",
        gap: "16px",
        flexShrink: 0,
        zIndex: 10,
      }}
    >
      {/* Interface Selector and Backend Status */}
      <div style={{ display: "flex", alignItems: "center", gap: "12px", minWidth: "320px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
          <Wifi size={16} style={{ color: "var(--color-accent-secondary)" }} />
          <label htmlFor="interface-select" style={{ fontSize: "11px", color: "var(--color-text-muted)", textTransform: "uppercase", fontWeight: 600 }}>
            Interface:
          </label>
        </div>

        <select
          id="interface-select"
          value={selectedInterface || ""}
          onChange={(e) => onSelectInterface(e.target.value)}
          disabled={isMonitoring}
          style={{
            maxWidth: "240px",
            fontSize: "12px",
            padding: "4px 8px",
            backgroundColor: "var(--color-bg)",
          }}
        >
          {interfaces.map((iface) => (
            <option key={iface.id} value={iface.friendly_name}>
              {iface.friendly_name} ({iface.ipv4_addresses[0] || "No IPv4"})
            </option>
          ))}
        </select>

        {/* Backend Tag */}
        <div
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "5px",
            padding: "3px 8px",
            borderRadius: "var(--radius-sm)",
            backgroundColor: "var(--color-surface-elevated)",
            border: "1px solid var(--color-border)",
            fontSize: "11px",
            color: "var(--color-text-secondary)",
            whiteSpace: "nowrap",
          }}
        >
          <HardDrive size={13} style={{ color: "var(--color-accent-primary)" }} />
          <span>{formatBackendName(activeBackend)}</span>
        </div>
      </div>

      {/* Global Search Bar */}
      <div style={{ flex: 1, maxWidth: "420px", position: "relative" }}>
        <Search
          size={14}
          style={{
            position: "absolute",
            left: "10px",
            top: "50%",
            transform: "translateY(-50%)",
            color: "var(--color-text-muted)",
          }}
        />
        <input
          type="search"
          placeholder="Filter traffic by IP, port, protocol, or domain..."
          value={searchQuery}
          onChange={(e) => onSearchChange(e.target.value)}
          style={{
            width: "100%",
            paddingLeft: "32px",
            paddingRight: "10px",
            fontSize: "12px",
            height: "32px",
            backgroundColor: "var(--color-bg)",
          }}
        />
      </div>

      {/* Action Controls */}
      <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
        {isMonitoring ? (
          <button
            onClick={onStopMonitoring}
            style={{
              backgroundColor: "var(--color-critical)",
              borderColor: "var(--color-critical)",
              color: "#FFFFFF",
              fontWeight: 600,
            }}
          >
            <Square size={14} fill="#FFFFFF" />
            <span>Stop Monitoring</span>
          </button>
        ) : (
          <button
            className="primary"
            onClick={onStartMonitoring}
            style={{ fontWeight: 600 }}
          >
            <Play size={14} fill="#FFFFFF" />
            <span>Start Monitoring</span>
          </button>
        )}

        {onToggleDensity && (
          <button
            className="ghost"
            onClick={onToggleDensity}
            title={isCompact ? "Switch to Standard View (Alt+D)" : "Switch to Compact High-Density View (Alt+D)"}
            aria-label="Toggle Density View"
            style={{
              padding: "5px 9px",
              fontSize: "11px",
              display: "flex",
              alignItems: "center",
              gap: "5px",
              backgroundColor: isCompact ? "var(--color-surface-hover)" : "transparent",
              border: `1px solid ${isCompact ? "var(--color-accent-primary)" : "var(--color-border)"}`,
              color: isCompact ? "var(--color-accent-primary)" : "var(--color-text-secondary)",
              fontWeight: isCompact ? 600 : 400,
            }}
          >
            {isCompact ? <Minimize2 size={13} /> : <Maximize2 size={13} />}
            <span>{isCompact ? "Compact" : "Standard"}</span>
          </button>
        )}

        {onToggleMute && (
          <button
            className="ghost"
            onClick={onToggleMute}
            title={isMuted ? "Unmute Sound Effects" : "Mute Sound Effects"}
            aria-label="Toggle Sound Effects"
            style={{
              padding: "6px",
              color: isMuted ? "var(--color-text-muted)" : "var(--color-accent-secondary)",
            }}
          >
            {isMuted ? <VolumeX size={16} /> : <Volume2 size={16} />}
          </button>
        )}

        {onOpenTutorial && (
          <button
            className="ghost"
            onClick={onOpenTutorial}
            title="Interactive User Guide & Tutorial"
            aria-label="How to Use"
            style={{
              padding: "5px 10px",
              fontSize: "11px",
              display: "flex",
              alignItems: "center",
              gap: "5px",
              border: "1px solid var(--color-border)",
              color: "var(--color-accent-primary)",
              backgroundColor: "rgba(56, 189, 248, 0.08)",
              borderRadius: "var(--radius-sm)",
              fontWeight: 600,
            }}
          >
            <HelpCircle size={13} style={{ color: "var(--color-accent-primary)" }} />
            <span>How to Use</span>
          </button>
        )}

        {onSelectTheme && (
          <div style={{ position: "relative" }}>
            <button
              className="ghost"
              onClick={() => setIsThemeDropdownOpen((prev) => !prev)}
              title="Switch Cyber Theme Palette"
              aria-label="Theme Switcher"
              style={{
                padding: "5px 8px",
                fontSize: "11px",
                display: "flex",
                alignItems: "center",
                gap: "5px",
                border: "1px solid var(--color-border)",
                color: "var(--color-accent-primary)",
              }}
            >
              <Palette size={13} />
              <span style={{ textTransform: "capitalize", fontSize: "11px" }}>
                {currentTheme.replace("cyberpunk-", "").replace("midnight-", "").replace("crimson-", "").replace("nordic-", "")}
              </span>
            </button>

            {isThemeDropdownOpen && (
              <div
                style={{
                  position: "absolute",
                  right: 0,
                  top: "calc(100% + 6px)",
                  backgroundColor: "var(--color-surface)",
                  border: "1px solid var(--color-border)",
                  borderRadius: "var(--radius-sm)",
                  boxShadow: "0 10px 28px rgba(0,0,0,0.55)",
                  padding: "5px",
                  display: "flex",
                  flexDirection: "column",
                  gap: "3px",
                  minWidth: "175px",
                  zIndex: 100,
                }}
              >
                {[
                  { id: "nordic-slate", label: "Nordic Slate", color: "#38BDF8", desc: "Cyan & Navy" },
                  { id: "cyberpunk-emerald", label: "Cyberpunk Emerald", color: "#10B981", desc: "Matrix Green" },
                  { id: "midnight-cobalt", label: "Midnight Cobalt", color: "#3B82F6", desc: "Electric Blue" },
                  { id: "crimson-lockdown", label: "Crimson Lockdown", color: "#F43F5E", desc: "Red Team SOC" },
                ].map((t) => {
                  const isCurrent = currentTheme === t.id;
                  return (
                    <button
                      key={t.id}
                      className="ghost"
                      onClick={() => {
                        onSelectTheme(t.id);
                        setIsThemeDropdownOpen(false);
                      }}
                      style={{
                        width: "100%",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        padding: "6px 8px",
                        fontSize: "11px",
                        fontWeight: isCurrent ? 700 : 400,
                        backgroundColor: isCurrent ? "var(--color-surface-hover)" : "transparent",
                        borderColor: isCurrent ? "var(--color-accent-primary)" : "transparent",
                        color: isCurrent ? "var(--color-text-primary)" : "var(--color-text-secondary)",
                        borderRadius: "var(--radius-sm)",
                      }}
                    >
                      <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                        <span
                          style={{
                            width: "9px",
                            height: "9px",
                            borderRadius: "50%",
                            backgroundColor: t.color,
                            boxShadow: `0 0 6px ${t.color}`,
                            flexShrink: 0,
                          }}
                        />
                        <span>{t.label}</span>
                      </div>
                      <span style={{ fontSize: "9px", color: "var(--color-text-muted)" }}>{t.desc}</span>
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        )}

        <button
          className="ghost"
          onClick={onOpenSettings}
          title="Open Settings"
          aria-label="Settings"
          style={{ padding: "6px" }}
        >
          <Sliders size={16} />
        </button>
      </div>
    </header>
  );
};
