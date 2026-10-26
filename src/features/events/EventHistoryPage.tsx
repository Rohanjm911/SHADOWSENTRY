import React, { useState, useMemo } from "react";
import { SecurityEvent, EventStatus, EventSeverity } from "../../types/event";
import { ThreatSeverityBadge } from "../../components/ThreatSeverityBadge";
import { ConfirmationDialog } from "../../components/ConfirmationDialog";
import { formatDateTime } from "../../lib/formatters";
import { TableEmptyRow } from "../../components/EmptyState";
import {
  History,
  Search,
  Filter,
  Download,
  Trash2,
  FileSpreadsheet,
  FileCode,
  CheckCircle2,
  Calendar,
  RefreshCw,
} from "lucide-react";

interface EventHistoryPageProps {
  events: SecurityEvent[];
  onSelectEvent: (event: SecurityEvent) => void;
  onExportJson: () => void;
  onExportCsv: () => void;
  onPurgeDatabase: (retentionDays?: number) => void;
  onRefresh: () => void;
}

export const EventHistoryPage: React.FC<EventHistoryPageProps> = ({
  events,
  onSelectEvent,
  onExportJson,
  onExportCsv,
  onPurgeDatabase,
  onRefresh,
}) => {
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState("ALL");
  const [selectedStatus, setSelectedStatus] = useState("ALL");
  const [isPurgeConfirmOpen, setIsPurgeConfirmOpen] = useState(false);

  const filteredEvents = useMemo(() => {
    return events.filter((e) => {
      if (selectedSeverity !== "ALL" && e.severity !== selectedSeverity) return false;
      if (selectedStatus !== "ALL" && e.status !== selectedStatus) return false;
      if (searchTerm.trim() !== "") {
        const q = searchTerm.toLowerCase();
        const matches =
          e.rule_name.toLowerCase().includes(q) ||
          e.what_observed.toLowerCase().includes(q) ||
          e.why_flagged.toLowerCase().includes(q) ||
          (e.source_ip && e.source_ip.toLowerCase().includes(q)) ||
          (e.dest_ip && e.dest_ip.toLowerCase().includes(q));
        if (!matches) return false;
      }
      return true;
    });
  }, [events, selectedSeverity, selectedStatus, searchTerm]);

  return (
    <div
      style={{
        flex: 1,
        display: "flex",
        flexDirection: "column",
        padding: "16px 20px",
        gap: "14px",
        overflow: "hidden",
        height: "100%",
      }}
    >
      {/* Action Header */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          flexWrap: "wrap",
          gap: "10px",
        }}
      >
        <div>
          <h2 style={{ fontSize: "16px", fontWeight: 700, color: "var(--color-text-primary)" }}>
            Security Event History
          </h2>
          <div style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>
            Searchable SQLite forensic timeline • {events.length} records stored locally
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <button className="ghost" onClick={onRefresh} title="Reload events">
            <RefreshCw size={13} />
            <span>Refresh</span>
          </button>

          <button onClick={onExportJson} title="Export sanitized JSON records">
            <FileCode size={13} />
            <span>Export JSON</span>
          </button>

          <button onClick={onExportCsv} title="Export sanitized CSV table">
            <FileSpreadsheet size={13} />
            <span>Export CSV</span>
          </button>

          <button
            onClick={() => setIsPurgeConfirmOpen(true)}
            style={{ color: "var(--color-critical)", borderColor: "var(--color-critical)" }}
            title="Permanently remove event records from local database"
          >
            <Trash2 size={13} />
            <span>Purge Records</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div
        style={{
          padding: "10px 14px",
          backgroundColor: "var(--color-surface)",
          border: "1px solid var(--color-border)",
          borderRadius: "var(--radius-sm)",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: "12px",
          flexWrap: "wrap",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
          {/* Severity selector */}
          <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
            <span style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>Severity:</span>
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              style={{ fontSize: "12px", padding: "3px 8px" }}
            >
              <option value="ALL">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="informational">Informational</option>
            </select>
          </div>

          {/* Status selector */}
          <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
            <span style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>Status:</span>
            <select
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value)}
              style={{ fontSize: "12px", padding: "3px 8px" }}
            >
              <option value="ALL">All Statuses</option>
              <option value="active">Active</option>
              <option value="investigating">Investigating</option>
              <option value="resolved">Resolved</option>
              <option value="dismissed">Dismissed</option>
            </select>
          </div>
        </div>

        {/* Search */}
        <div style={{ position: "relative" }}>
          <Search
            size={13}
            style={{
              position: "absolute",
              left: "8px",
              top: "50%",
              transform: "translateY(-50%)",
              color: "var(--color-text-muted)",
            }}
          />
          <input
            type="text"
            placeholder="Search events by rule, IP, or evidence..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              paddingLeft: "26px",
              fontSize: "12px",
              height: "28px",
              width: "280px",
            }}
          />
        </div>
      </div>

      {/* Forensic Table */}
      <div
        className="table-wrapper"
        tabIndex={0}
        role="region"
        aria-label="Event history table"
        style={{ flex: 1, minHeight: 0 }}
      >
        <table>
          <thead>
            <tr>
              <th style={{ width: "95px" }}>Severity</th>
              <th style={{ width: "130px" }}>Rule ID</th>
              <th>Rule Name & Observed Evidence</th>
              <th>Source Host</th>
              <th>Destination Host</th>
              <th style={{ width: "80px" }}>Confidence</th>
              <th style={{ width: "95px" }}>Status</th>
              <th style={{ width: "140px" }}>Recorded Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {filteredEvents.length === 0 ? (
              <TableEmptyRow
                colSpan={8}
                title={searchTerm.trim() !== "" || selectedSeverity !== "ALL" || selectedStatus !== "ALL"
                  ? "No Historical Records Match Filter"
                  : "Forensic Timeline Clear — Zero Historical Threats"}
                description={searchTerm.trim() !== "" || selectedSeverity !== "ALL" || selectedStatus !== "ALL"
                  ? "Try broadening your search term or resetting the severity filter."
                  : "All captured events conform to baseline. No security anomalies logged in SQLite store."}
                badgeText="Local SQLite WAL Storage Clean"
                iconType={searchTerm.trim() !== "" || selectedSeverity !== "ALL" || selectedStatus !== "ALL" ? "search" : "success"}
              />
            ) : (
              filteredEvents.map((evt) => (
                <tr
                  key={evt.event_id}
                  onClick={() => onSelectEvent(evt)}
                  style={{ cursor: "pointer" }}
                >
                  <td>
                    <ThreatSeverityBadge severity={evt.severity} />
                  </td>
                  <td className="font-mono" style={{ fontSize: "11px", color: "var(--color-text-secondary)" }}>
                    {evt.rule_id}
                  </td>
                  <td style={{ maxWidth: "320px", overflow: "hidden", textOverflow: "ellipsis" }}>
                    <div style={{ fontWeight: 600, color: "var(--color-text-primary)" }}>{evt.rule_name}</div>
                    <div style={{ fontSize: "11px", color: "var(--color-text-muted)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {evt.what_observed}
                    </div>
                  </td>
                  <td className="font-mono" style={{ fontSize: "11px" }}>
                    {evt.source_ip ? `${evt.source_ip}${evt.source_port ? `:${evt.source_port}` : ""}` : "—"}
                  </td>
                  <td className="font-mono" style={{ fontSize: "11px" }}>
                    {evt.dest_ip ? `${evt.dest_ip}${evt.dest_port ? `:${evt.dest_port}` : ""}` : "—"}
                  </td>
                  <td className="font-mono" style={{ fontSize: "11px" }}>
                    {Math.round(evt.confidence_score * 100)}%
                  </td>
                  <td>
                    <span
                      className="badge"
                      style={{
                        backgroundColor:
                          evt.status === "active"
                            ? "#2A1215"
                            : evt.status === "investigating"
                            ? "#28200F"
                            : "#10261E",
                        borderColor:
                          evt.status === "active"
                            ? "var(--color-critical)"
                            : evt.status === "investigating"
                            ? "var(--color-warning)"
                            : "var(--color-success)",
                        color:
                          evt.status === "active"
                            ? "var(--color-critical)"
                            : evt.status === "investigating"
                            ? "var(--color-warning)"
                            : "var(--color-success)",
                      }}
                    >
                      {evt.status}
                    </span>
                  </td>
                  <td style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>
                    {formatDateTime(evt.timestamp)}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Confirmation Dialog for Purging Database */}
      <ConfirmationDialog
        isOpen={isPurgeConfirmOpen}
        title="Permanently Purge Local Event Records?"
        description="This action will delete all recorded security findings, honeypot probe records, and historical monitoring sessions from the local SQLite database. This operation cannot be undone."
        confirmLabel="Purge All Records"
        cancelLabel="Keep Records"
        isDestructive={true}
        onConfirm={() => {
          onPurgeDatabase();
          setIsPurgeConfirmOpen(false);
        }}
        onCancel={() => setIsPurgeConfirmOpen(false)}
      />
    </div>
  );
};
