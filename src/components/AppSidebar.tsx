import React from "react";
import {
  LayoutDashboard,
  Activity,
  Globe,
  ShieldAlert,
  FlaskConical,
  History,
  FileText,
  Settings,
  Shield,
  Circle,
  HelpCircle,
} from "lucide-react";

export type NavTab =
  | "dashboard"
  | "traffic"
  | "dns"
  | "threats"
  | "honeypot"
  | "events"
  | "reports"
  | "settings";

interface AppSidebarProps {
  activeTab: NavTab;
  onTabChange: (tab: NavTab) => void;
  isMonitoring: boolean;
  activeThreatCount: number;
  honeypotProbeCount: number;
  onOpenTutorial?: () => void;
}

export const AppSidebar: React.FC<AppSidebarProps> = ({
  activeTab,
  onTabChange,
  isMonitoring,
  activeThreatCount,
  honeypotProbeCount,
  onOpenTutorial,
}) => {
  const navItems: { id: NavTab; label: string; icon: React.ElementType; badge?: number; badgeColor?: string }[] = [
    { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
    { id: "traffic", label: "Live Traffic", icon: Activity },
    { id: "dns", label: "DNS Monitor", icon: Globe },
    {
      id: "threats",
      label: "Threat Center",
      icon: ShieldAlert,
      badge: activeThreatCount > 0 ? activeThreatCount : undefined,
      badgeColor: "var(--color-critical)",
    },
    {
      id: "honeypot",
      label: "Honeypot Lab",
      icon: FlaskConical,
      badge: honeypotProbeCount > 0 ? honeypotProbeCount : undefined,
      badgeColor: "var(--color-warning)",
    },
    { id: "events", label: "Event History", icon: History },
    { id: "reports", label: "Security Reports", icon: FileText },
    { id: "settings", label: "Settings & Privacy", icon: Settings },
  ];

  return (
    <aside
      style={{
        width: "var(--sidebar-width)",
        backgroundColor: "var(--color-sidebar)",
        borderRight: "1px solid var(--color-border)",
        display: "flex",
        flexDirection: "column",
        height: "100%",
        flexShrink: 0,
        userSelect: "none",
      }}
    >
      {/* Brand Header */}
      <div
        style={{
          padding: "18px 16px 14px 16px",
          borderBottom: "1px solid var(--color-border)",
          display: "flex",
          alignItems: "center",
          gap: "12px",
        }}
      >
        <div
          style={{
            width: "38px",
            height: "38px",
            backgroundColor: "rgba(16, 22, 30, 0.8)",
            border: "1px solid var(--color-border)",
            borderRadius: "var(--radius-md)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexShrink: 0,
            overflow: "hidden",
            boxShadow: "0 0 12px rgba(53, 201, 138, 0.2)",
          }}
        >
          <img
            src="/logo.png"
            alt="SHADOWSENTRY"
            style={{ width: "100%", height: "100%", objectFit: "contain" }}
          />
        </div>
        <div style={{ overflow: "hidden" }}>
          <div
            style={{
              fontSize: "14px",
              fontWeight: 700,
              letterSpacing: "0.06em",
              color: "var(--color-text-primary)",
              lineHeight: 1.2,
            }}
          >
            SHADOWSENTRY
          </div>
          <div
            style={{
              fontSize: "10px",
              color: "var(--color-text-muted)",
              whiteSpace: "nowrap",
              textOverflow: "ellipsis",
              overflow: "hidden",
            }}
          >
            Invisible Threats. Visible Intelligence.
          </div>
        </div>
      </div>

      {/* Monitoring Status Indicator Banner */}
      <div
        style={{
          padding: "10px 16px",
          backgroundColor: isMonitoring ? "#10261E" : "#1B232E",
          borderBottom: "1px solid var(--color-border)",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          fontSize: "11px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <div
            className={isMonitoring ? "animate-pulse-live" : ""}
            style={{
              width: "8px",
              height: "8px",
              borderRadius: "50%",
              backgroundColor: isMonitoring ? "var(--color-success)" : "var(--color-text-muted)",
              flexShrink: 0,
            }}
          />
          <span style={{ color: isMonitoring ? "var(--color-success)" : "var(--color-text-secondary)", fontWeight: 600 }}>
            {isMonitoring ? "SENTRY MONITORING" : "MONITORING IDLE"}
          </span>
        </div>
        <span style={{ fontSize: "10px", color: "var(--color-text-muted)" }}>
          {isMonitoring ? "Live Capture" : "Standby"}
        </span>
      </div>

      {/* Navigation List */}
      <nav
        style={{
          flex: 1,
          padding: "12px 8px",
          display: "flex",
          flexDirection: "column",
          gap: "2px",
          overflowY: "auto",
        }}
      >
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              className="nav-tab-button"
              onClick={() => onTabChange(item.id)}
              style={{
                width: "100%",
                padding: "8px 12px",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                backgroundColor: isActive ? "var(--color-surface-elevated)" : "transparent",
                borderColor: isActive ? "var(--color-border)" : "transparent",
                borderLeft: isActive ? "3px solid var(--color-accent-primary)" : "3px solid transparent",
                borderRadius: isActive ? "0 var(--radius-sm) var(--radius-sm) 0" : "var(--radius-sm)",
                color: isActive ? "var(--color-text-primary)" : "var(--color-text-secondary)",
                fontWeight: isActive ? 600 : 400,
                textAlign: "left",
                cursor: "pointer",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                <span
                  style={{
                    color: isActive ? "var(--color-accent-primary)" : "var(--color-text-muted)",
                    display: "flex",
                  }}
                >
                  <Icon size={16} />
                </span>
                <span style={{ fontSize: "13px" }}>{item.label}</span>
              </div>
              {item.badge !== undefined && (
                <span
                  style={{
                    backgroundColor: item.badgeColor || "var(--color-accent-primary)",
                    color: "#FFFFFF",
                    fontSize: "10px",
                    fontWeight: 700,
                    padding: "1px 6px",
                    borderRadius: "10px",
                    minWidth: "18px",
                    textAlign: "center",
                  }}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}

        {onOpenTutorial && (
          <div style={{ marginTop: "auto", paddingTop: "10px", borderTop: "1px solid var(--color-border)" }}>
            <button
              onClick={onOpenTutorial}
              className="nav-tab-button"
              style={{
                width: "100%",
                padding: "8px 12px",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                backgroundColor: "rgba(56, 189, 248, 0.08)",
                border: "1px solid rgba(56, 189, 248, 0.28)",
                borderRadius: "var(--radius-sm)",
                color: "var(--color-accent-primary)",
                fontWeight: 600,
                textAlign: "left",
                cursor: "pointer",
                transition: "all 0.18s ease",
              }}
              title="Open Interactive How to Use Tutorial Guide"
            >
              <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                <span style={{ display: "flex", color: "var(--color-accent-primary)" }}>
                  <HelpCircle size={16} />
                </span>
                <span style={{ fontSize: "13px" }}>How to Use</span>
              </div>
              <span
                style={{
                  fontSize: "9.5px",
                  fontWeight: 700,
                  backgroundColor: "rgba(56, 189, 248, 0.2)",
                  color: "var(--color-accent-primary)",
                  padding: "1px 6px",
                  borderRadius: "10px",
                  letterSpacing: "0.04em",
                }}
              >
                TUTORIAL
              </span>
            </button>
          </div>
        )}
      </nav>

      {/* System Integrity Info in Sidebar Footer */}
      <div
        style={{
          padding: "12px 16px",
          borderTop: "1px solid var(--color-border)",
          backgroundColor: "var(--color-bg)",
          fontSize: "11px",
          color: "var(--color-text-muted)",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "4px" }}>
          <span>Storage</span>
          <span style={{ color: "var(--color-text-secondary)", fontFamily: "var(--font-mono)" }}>SQLite Local</span>
        </div>
        <div style={{ display: "flex", justifyContent: "space-between" }}>
          <span>Telemetry</span>
          <span style={{ color: "var(--color-success)", fontWeight: 500 }}>Disabled (Private)</span>
        </div>
      </div>
    </aside>
  );
};
