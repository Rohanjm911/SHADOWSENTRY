import React from "react";
import { formatDuration } from "../lib/formatters";
import { Database, ShieldCheck, UserCheck, Clock, Network } from "lucide-react";

interface BottomStatusBarProps {
  isMonitoring: boolean;
  durationSeconds: number;
  interfaceName: string | null;
  packetCount: number;
  isElevated: boolean;
}

export const BottomStatusBar: React.FC<BottomStatusBarProps> = ({
  isMonitoring,
  durationSeconds,
  interfaceName,
  packetCount,
  isElevated,
}) => {
  return (
    <footer
      style={{
        height: "var(--bottombar-height)",
        backgroundColor: "var(--color-sidebar)",
        borderTop: "1px solid var(--color-border)",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "0 14px",
        fontSize: "11px",
        color: "var(--color-text-secondary)",
        flexShrink: 0,
        userSelect: "none",
        zIndex: 10,
      }}
    >
      {/* Left: App Version & Session Timer */}
      <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
        <span style={{ fontWeight: 600, color: "var(--color-text-primary)" }}>
          SHADOWSENTRY <span style={{ color: "var(--color-text-muted)", fontWeight: 400 }}>v0.1.0 (Windows x64)</span>
        </span>

        <div style={{ display: "flex", alignItems: "center", gap: "5px" }}>
          <Clock size={13} style={{ color: "var(--color-text-muted)" }} />
          <span>
            {isMonitoring ? `Elapsed: ${formatDuration(durationSeconds)}` : "Session: Standby"}
          </span>
        </div>

        {isMonitoring && (
          <div style={{ display: "flex", alignItems: "center", gap: "5px" }}>
            <Network size={13} style={{ color: "var(--color-accent-secondary)" }} />
            <span>{interfaceName || "Default"} — {packetCount.toLocaleString()} pkts</span>
          </div>
        )}
      </div>

      {/* Right: Security & Database Integrity Indicators */}
      <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
        {/* Elevation Status */}
        <div style={{ display: "flex", alignItems: "center", gap: "5px" }}>
          <UserCheck size={13} style={{ color: isElevated ? "var(--color-success)" : "var(--color-warning)" }} />
          <span>{isElevated ? "Elevated (Admin)" : "Standard User"}</span>
        </div>

        {/* Local Storage */}
        <div style={{ display: "flex", alignItems: "center", gap: "5px" }}>
          <Database size={13} style={{ color: "var(--color-accent-primary)" }} />
          <span>SQLite WAL Local</span>
        </div>

        {/* Privacy Boundary */}
        <div style={{ display: "flex", alignItems: "center", gap: "5px" }}>
          <ShieldCheck size={13} style={{ color: "var(--color-success)" }} />
          <span style={{ color: "var(--color-success)" }}>Offline-First</span>
        </div>
      </div>
    </footer>
  );
};
