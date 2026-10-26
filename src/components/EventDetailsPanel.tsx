import React, { useState } from "react";
import { SecurityEvent, EventStatus } from "../types/event";
import { ThreatSeverityBadge } from "./ThreatSeverityBadge";
import { formatDateTime, formatConfidence } from "../lib/formatters";
import {
  X,
  Shield,
  HelpCircle,
  ListChecks,
  CheckCircle,
  XCircle,
  Search,
  FileText,
  Clock,
  Layers,
} from "lucide-react";

interface EventDetailsPanelProps {
  event: SecurityEvent | null;
  onClose: () => void;
  onUpdateStatus: (eventId: string, newStatus: EventStatus, notes?: string) => void;
}

export const EventDetailsPanel: React.FC<EventDetailsPanelProps> = ({
  event,
  onClose,
  onUpdateStatus,
}) => {
  const [notes, setNotes] = useState(event?.user_notes || "");
  const [isEditingNotes, setIsEditingNotes] = useState(false);

  if (!event) return null;

  const confidence = formatConfidence(event.confidence_score);

  const handleSaveNotes = () => {
    onUpdateStatus(event.event_id, event.status, notes);
    setIsEditingNotes(false);
  };

  return (
    <div
      className="animate-slide-in"
      style={{
        width: "480px",
        backgroundColor: "var(--color-surface)",
        borderLeft: "1px solid var(--color-border)",
        boxShadow: "-8px 0 24px rgba(0, 0, 0, 0.45)",
        display: "flex",
        flexDirection: "column",
        height: "100%",
        flexShrink: 0,
        overflowY: "auto",
        zIndex: 20,
      }}
    >
      {/* Header */}
      <div
        style={{
          padding: "16px",
          borderBottom: "1px solid var(--color-border)",
          display: "flex",
          alignItems: "flex-start",
          justifyContent: "space-between",
          gap: "12px",
          backgroundColor: "var(--color-surface-elevated)",
        }}
      >
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
            <ThreatSeverityBadge severity={event.severity} />
            <span style={{ fontSize: "11px", color: "var(--color-text-muted)", fontFamily: "var(--font-mono)" }}>
              {event.rule_id}
            </span>
          </div>
          <h2 style={{ fontSize: "15px", fontWeight: 600, color: "var(--color-text-primary)", lineHeight: 1.3 }}>
            {event.rule_name}
          </h2>
          <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "11px", color: "var(--color-text-secondary)", marginTop: "4px" }}>
            <Clock size={12} />
            <span>{formatDateTime(event.timestamp)}</span>
          </div>
        </div>

        <button className="ghost" onClick={onClose} aria-label="Close details" style={{ padding: "4px" }}>
          <X size={16} />
        </button>
      </div>

      {/* Main Content Body */}
      <div style={{ padding: "16px", display: "flex", flexDirection: "column", gap: "20px" }}>
        
        {/* Status and Action Buttons */}
        <div
          style={{
            padding: "12px",
            backgroundColor: "var(--color-bg)",
            border: "1px solid var(--color-border)",
            borderRadius: "var(--radius-sm)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <div>
            <div style={{ fontSize: "10px", color: "var(--color-text-muted)", textTransform: "uppercase" }}>Current Status</div>
            <div style={{ fontSize: "12px", fontWeight: 600, color: "var(--color-text-primary)", textTransform: "capitalize" }}>
              {event.status}
            </div>
          </div>

          <div style={{ display: "flex", gap: "6px" }}>
            {event.status !== "investigating" && (
              <button
                onClick={() => onUpdateStatus(event.event_id, "investigating")}
                style={{ fontSize: "11px", padding: "4px 8px" }}
              >
                <Search size={12} />
                <span>Investigate</span>
              </button>
            )}
            {event.status !== "resolved" && (
              <button
                onClick={() => onUpdateStatus(event.event_id, "resolved")}
                style={{ fontSize: "11px", padding: "4px 8px", backgroundColor: "#10261E", borderColor: "var(--color-success)", color: "var(--color-success)" }}
              >
                <CheckCircle size={12} />
                <span>Resolve</span>
              </button>
            )}
            {event.status !== "dismissed" && (
              <button
                onClick={() => onUpdateStatus(event.event_id, "dismissed")}
                style={{ fontSize: "11px", padding: "4px 8px", color: "var(--color-text-muted)" }}
              >
                <XCircle size={12} />
                <span>Dismiss</span>
              </button>
            )}
          </div>
        </div>

        {/* Section: What Was Observed */}
        <div>
          <h3 style={{ fontSize: "12px", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.05em", color: "var(--color-accent-primary)", marginBottom: "6px", display: "flex", alignItems: "center", gap: "6px" }}>
            <FileText size={14} />
            <span>1. What Was Observed</span>
          </h3>
          <p style={{ fontSize: "13px", color: "var(--color-text-primary)", lineHeight: 1.5, backgroundColor: "var(--color-bg)", padding: "10px", borderRadius: "var(--radius-sm)", border: "1px solid var(--color-border-subtle)" }}>
            {event.what_observed}
          </p>
        </div>

        {/* Section: Why Flagged */}
        <div>
          <h3 style={{ fontSize: "12px", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.05em", color: "var(--color-warning)", marginBottom: "6px", display: "flex", alignItems: "center", gap: "6px" }}>
            <Shield size={14} />
            <span>2. Why It Was Flagged</span>
          </h3>
          <p style={{ fontSize: "13px", color: "var(--color-text-primary)", lineHeight: 1.5, backgroundColor: "var(--color-bg)", padding: "10px", borderRadius: "var(--radius-sm)", border: "1px solid var(--color-border-subtle)" }}>
            {event.why_flagged}
          </p>
        </div>

        {/* Section: Supporting Evidence */}
        <div>
          <h3 style={{ fontSize: "12px", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.05em", color: "var(--color-accent-secondary)", marginBottom: "8px", display: "flex", alignItems: "center", gap: "6px" }}>
            <Layers size={14} />
            <span>3. Supporting Evidence</span>
          </h3>
          <div style={{ border: "1px solid var(--color-border)", borderRadius: "var(--radius-sm)", overflow: "hidden" }}>
            <table style={{ width: "100%", fontSize: "12px" }}>
              <tbody>
                {event.supporting_evidence.map((ev, i) => (
                  <tr key={i} style={{ borderBottom: "1px solid var(--color-border-subtle)" }}>
                    <td style={{ padding: "8px 12px", color: "var(--color-text-secondary)", width: "40%", fontWeight: 500, backgroundColor: "var(--color-surface-elevated)" }}>
                      {ev.label}
                    </td>
                    <td
                      style={{
                        padding: "8px 12px",
                        fontFamily: "var(--font-mono)",
                        color: ev.highlight ? "var(--color-accent-primary)" : "var(--color-text-primary)",
                        fontWeight: ev.highlight ? 600 : 400,
                      }}
                    >
                      {String(ev.value)}
                    </td>
                  </tr>
                ))}
                {event.source_ip && (
                  <tr style={{ borderBottom: "1px solid var(--color-border-subtle)" }}>
                    <td style={{ padding: "8px 12px", color: "var(--color-text-secondary)", backgroundColor: "var(--color-surface-elevated)" }}>Source</td>
                    <td style={{ padding: "8px 12px", fontFamily: "var(--font-mono)" }}>
                      {event.source_ip}{event.source_port ? `:${event.source_port}` : ""}
                    </td>
                  </tr>
                )}
                {event.dest_ip && (
                  <tr>
                    <td style={{ padding: "8px 12px", color: "var(--color-text-secondary)", backgroundColor: "var(--color-surface-elevated)" }}>Destination</td>
                    <td style={{ padding: "8px 12px", fontFamily: "var(--font-mono)" }}>
                      {event.dest_ip}{event.dest_port ? `:${event.dest_port}` : ""}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Section: Uncertainty & Caveats */}
        <div>
          <h3 style={{ fontSize: "12px", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.05em", color: "var(--color-text-secondary)", marginBottom: "6px", display: "flex", alignItems: "center", gap: "6px" }}>
            <HelpCircle size={14} />
            <span>4. Uncertainty & Heuristic Caveats</span>
          </h3>
          <div style={{ backgroundColor: "#151B24", padding: "10px", borderRadius: "var(--radius-sm)", border: "1px solid var(--color-border)" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "6px", fontSize: "11px" }}>
              <span style={{ color: "var(--color-text-muted)" }}>Confidence Score:</span>
              <span style={{ fontWeight: 600, color: "var(--color-text-primary)" }}>
                {confidence.percent} ({confidence.label})
              </span>
            </div>
            <p style={{ fontSize: "12px", color: "var(--color-text-secondary)", lineHeight: 1.45 }}>
              {event.uncertainty_details}
            </p>
          </div>
        </div>

        {/* Section: Recommended Next Steps */}
        <div>
          <h3 style={{ fontSize: "12px", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.05em", color: "var(--color-success)", marginBottom: "8px", display: "flex", alignItems: "center", gap: "6px" }}>
            <ListChecks size={14} />
            <span>5. Recommended Investigation Steps</span>
          </h3>
          <ol style={{ paddingLeft: "18px", fontSize: "12px", color: "var(--color-text-primary)", display: "flex", flexDirection: "column", gap: "6px", lineHeight: 1.45 }}>
            {event.recommended_steps.map((step, idx) => (
              <li key={idx}>{step}</li>
            ))}
          </ol>
        </div>

        {/* Section: Investigation Notes */}
        <div style={{ borderTop: "1px solid var(--color-border)", paddingTop: "14px" }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "8px" }}>
            <span style={{ fontSize: "12px", fontWeight: 600, color: "var(--color-text-primary)" }}>
              Investigator Notes
            </span>
            {!isEditingNotes ? (
              <button className="ghost" onClick={() => setIsEditingNotes(true)} style={{ fontSize: "11px", padding: "2px 6px" }}>
                Edit Notes
              </button>
            ) : (
              <button className="primary" onClick={handleSaveNotes} style={{ fontSize: "11px", padding: "2px 8px" }}>
                Save
              </button>
            )}
          </div>

          {isEditingNotes ? (
            <textarea
              rows={3}
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="Record forensic observations, asset owner verification, or false positive rationale..."
              style={{ width: "100%", fontSize: "12px", backgroundColor: "var(--color-bg)" }}
            />
          ) : (
            <div style={{ fontSize: "12px", color: event.user_notes ? "var(--color-text-primary)" : "var(--color-text-muted)", fontStyle: event.user_notes ? "normal" : "italic", backgroundColor: "var(--color-bg)", padding: "8px", borderRadius: "var(--radius-sm)", border: "1px solid var(--color-border-subtle)" }}>
              {event.user_notes || "No notes attached to this finding. Click 'Edit Notes' to record evidence."}
            </div>
          )}
        </div>

      </div>
    </div>
  );
};
