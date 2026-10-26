import React from "react";
import { AlertCircle, Inbox, Loader2, ShieldCheck, CheckCircle2, Search, Radio, Filter } from "lucide-react";

interface EmptyStateProps {
  title: string;
  description: string;
  action?: {
    label: string;
    onClick: () => void;
  };
}

export const EmptyState: React.FC<EmptyStateProps> = ({ title, description, action }) => (
  <div
    style={{
      padding: "48px 24px",
      textAlign: "center",
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      justifyContent: "center",
      color: "var(--color-text-secondary)",
    }}
  >
    <div
      style={{
        padding: "12px",
        backgroundColor: "var(--color-surface-elevated)",
        borderRadius: "50%",
        marginBottom: "14px",
        color: "var(--color-text-muted)",
      }}
    >
      <Inbox size={28} />
    </div>
    <h3 style={{ fontSize: "14px", fontWeight: 600, color: "var(--color-text-primary)", marginBottom: "6px" }}>
      {title}
    </h3>
    <p style={{ fontSize: "13px", maxWidth: "420px", marginBottom: action ? "16px" : 0 }}>
      {description}
    </p>
    {action && (
      <button className="primary" onClick={action.onClick}>
        {action.label}
      </button>
    )}
  </div>
);

export interface SecurityClearEmptyStateProps {
  title: string;
  description: string;
  badgeText?: string;
  iconType?: "success" | "info" | "search";
  compact?: boolean;
  action?: {
    label: string;
    onClick: () => void;
  };
}

export const SecurityClearEmptyState: React.FC<SecurityClearEmptyStateProps> = ({
  title,
  description,
  badgeText,
  iconType = "success",
  compact = false,
  action,
}) => {
  const isSuccess = iconType === "success";
  const isSearch = iconType === "search";

  const iconColor = isSuccess
    ? "var(--color-success)"
    : isSearch
    ? "var(--color-text-muted)"
    : "var(--color-accent-primary)";
  const bg = isSuccess
    ? "rgba(52, 211, 153, 0.12)"
    : isSearch
    ? "rgba(148, 163, 184, 0.1)"
    : "rgba(56, 189, 248, 0.12)";
  const border = isSuccess
    ? "rgba(52, 211, 153, 0.28)"
    : isSearch
    ? "rgba(148, 163, 184, 0.2)"
    : "rgba(56, 189, 248, 0.28)";
  const glow = isSuccess ? "0 0 16px rgba(52, 211, 153, 0.15)" : "none";

  return (
    <div
      style={{
        padding: compact ? "20px 16px" : "36px 20px",
        textAlign: "center",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        width: "100%",
        whiteSpace: "normal",
      }}
    >
      <div
        style={{
          width: compact ? "36px" : "44px",
          height: compact ? "36px" : "44px",
          borderRadius: "50%",
          backgroundColor: bg,
          border: `1px solid ${border}`,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          color: iconColor,
          marginBottom: compact ? "8px" : "12px",
          boxShadow: glow,
        }}
      >
        {isSuccess ? (
          <ShieldCheck size={compact ? 18 : 22} />
        ) : isSearch ? (
          <Filter size={compact ? 16 : 20} />
        ) : (
          <Radio size={compact ? 16 : 20} />
        )}
      </div>

      <h4
        style={{
          fontSize: compact ? "12.5px" : "13.5px",
          fontWeight: 600,
          color: "var(--color-text-primary)",
          letterSpacing: "0.01em",
          margin: "0 0 4px 0",
        }}
      >
        {title}
      </h4>

      <p
        style={{
          fontSize: compact ? "11px" : "12px",
          color: "var(--color-text-muted)",
          maxWidth: "420px",
          lineHeight: 1.5,
          margin: 0,
        }}
      >
        {description}
      </p>

      {badgeText && (
        <span
          style={{
            marginTop: "10px",
            display: "inline-flex",
            alignItems: "center",
            gap: "5px",
            padding: "2px 8px",
            borderRadius: "10px",
            backgroundColor: "var(--color-surface-elevated)",
            border: "1px solid var(--color-border-subtle)",
            fontSize: "10.5px",
            color: "var(--color-text-secondary)",
            fontFamily: "var(--font-mono)",
          }}
        >
          <span style={{ width: 5, height: 5, borderRadius: "50%", backgroundColor: iconColor }} />
          {badgeText}
        </span>
      )}

      {action && (
        <button
          onClick={action.onClick}
          style={{
            marginTop: "12px",
            fontSize: "11px",
            padding: "4px 10px",
          }}
        >
          {action.label}
        </button>
      )}
    </div>
  );
};

export interface TableEmptyRowProps {
  colSpan: number;
  title: string;
  description?: string;
  badgeText?: string;
  iconType?: "success" | "info" | "search";
  compact?: boolean;
}

export const TableEmptyRow: React.FC<TableEmptyRowProps> = ({
  colSpan,
  title,
  description,
  badgeText,
  iconType = "success",
  compact = false,
}) => (
  <tr>
    <td
      colSpan={colSpan}
      style={{
        padding: "0",
        backgroundColor: "transparent",
        whiteSpace: "normal",
        borderBottom: "none",
      }}
    >
      <SecurityClearEmptyState
        title={title}
        description={description || ""}
        badgeText={badgeText}
        iconType={iconType}
        compact={compact}
      />
    </td>
  </tr>
);

export const LoadingState: React.FC<{ message?: string }> = ({ message = "Loading network data..." }) => (
  <div
    style={{
      padding: "48px 24px",
      textAlign: "center",
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      justifyContent: "center",
      color: "var(--color-text-secondary)",
      gap: "12px",
    }}
  >
    <Loader2 size={24} className="spin" style={{ color: "var(--color-accent-primary)" }} />
    <span style={{ fontSize: "13px" }}>{message}</span>
  </div>
);

export const ErrorState: React.FC<{ title?: string; message: string; onRetry?: () => void }> = ({
  title = "Operation Encountered an Issue",
  message,
  onRetry,
}) => (
  <div
    style={{
      padding: "24px",
      backgroundColor: "#2A1215",
      border: "1px solid var(--color-critical)",
      borderRadius: "var(--radius-md)",
      color: "var(--color-critical)",
      display: "flex",
      alignItems: "flex-start",
      gap: "12px",
      margin: "12px 0",
    }}
  >
    <AlertCircle size={20} style={{ flexShrink: 0, marginTop: "2px" }} />
    <div style={{ flex: 1 }}>
      <h4 style={{ fontSize: "13px", fontWeight: 600, marginBottom: "4px" }}>{title}</h4>
      <p style={{ fontSize: "12px", color: "var(--color-text-primary)", lineHeight: 1.4 }}>{message}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          style={{
            marginTop: "10px",
            backgroundColor: "var(--color-critical)",
            borderColor: "var(--color-critical)",
            color: "#FFFFFF",
          }}
        >
          Retry Operation
        </button>
      )}
    </div>
  </div>
);
