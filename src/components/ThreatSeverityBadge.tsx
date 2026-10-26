import React from "react";
import { EventSeverity } from "../types/event";
import { ShieldAlert, AlertTriangle, AlertCircle, Info } from "lucide-react";

interface ThreatSeverityBadgeProps {
  severity: EventSeverity;
  showIcon?: boolean;
}

export const ThreatSeverityBadge: React.FC<ThreatSeverityBadgeProps> = ({
  severity,
  showIcon = true,
}) => {
  const config = {
    critical: {
      label: "Critical",
      bg: "#2A1215",
      border: "#FF5D68",
      text: "#FF5D68",
      icon: ShieldAlert,
    },
    high: {
      label: "High",
      bg: "#2A1810",
      border: "#FF8A3D",
      text: "#FF8A3D",
      icon: AlertTriangle,
    },
    medium: {
      label: "Medium",
      bg: "#28200F",
      border: "#F4B942",
      text: "#F4B942",
      icon: AlertTriangle,
    },
    low: {
      label: "Low",
      bg: "#10232A",
      border: "#45C6D8",
      text: "#45C6D8",
      icon: AlertCircle,
    },
    informational: {
      label: "Info",
      bg: "#131E2E",
      border: "#4C8DFF",
      text: "#4C8DFF",
      icon: Info,
    },
  }[severity] || {
    label: severity,
    bg: "#151D27",
    border: "#6C7A8E",
    text: "#A8B3C2",
    icon: Info,
  };

  const IconComp = config.icon;

  return (
    <span
      className={`badge ${severity === "critical" ? "animate-pulse-critical" : ""}`}
      style={{
        backgroundColor: config.bg,
        borderColor: config.border,
        color: config.text,
      }}
    >
      {showIcon && <IconComp size={12} strokeWidth={2.5} />}
      <span>{config.label}</span>
    </span>
  );
};
