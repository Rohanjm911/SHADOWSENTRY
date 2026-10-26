import React, { useState, useMemo } from "react";
import { DnsQueryRecord } from "../../types/packet";
import { formatDateTime } from "../../lib/formatters";
import { TableEmptyRow } from "../../components/EmptyState";
import {
  Globe,
  Search,
  ShieldAlert,
  AlertTriangle,
  Info,
  CheckCircle,
  Lock,
  ExternalLink,
} from "lucide-react";

interface DnsMonitorPageProps {
  queries: DnsQueryRecord[];
  isMonitoring: boolean;
}

export const DnsMonitorPage: React.FC<DnsMonitorPageProps> = ({ queries, isMonitoring }) => {
  const [searchTerm, setSearchTerm] = useState("");
  const [onlySuspicious, setOnlySuspicious] = useState(false);
  const [selectedRecordType, setSelectedRecordType] = useState("ALL");
  const [selectedQuery, setSelectedQuery] = useState<DnsQueryRecord | null>(null);

  const filteredQueries = useMemo(() => {
    return queries.filter((q) => {
      if (onlySuspicious && !q.is_suspicious) return false;
      if (selectedRecordType !== "ALL" && q.record_type !== selectedRecordType) return false;
      if (searchTerm.trim() !== "") {
        const s = searchTerm.toLowerCase();
        const matches =
          q.query_name.toLowerCase().includes(s) ||
          q.client_ip.toLowerCase().includes(s) ||
          q.server_ip.toLowerCase().includes(s) ||
          q.resolved_ips.some((ip) => ip.toLowerCase().includes(s));
        if (!matches) return false;
      }
      return true;
    });
  }, [queries, onlySuspicious, selectedRecordType, searchTerm]);

  const suspiciousCount = queries.filter((q) => q.is_suspicious).length;

  return (
    <div style={{ display: "flex", height: "100%", width: "100%", overflow: "hidden" }}>
      {/* Main Table Column */}
      <div
        style={{
          flex: 1,
          display: "flex",
          flexDirection: "column",
          padding: "16px 20px",
          gap: "12px",
          overflow: "hidden",
          minWidth: 0,
        }}
      >
        {/* Banner Explaining DNS Visibility & Encrypted DNS (DoH/DoT) Boundaries */}
        <div
          style={{
            padding: "10px 14px",
            backgroundColor: "#131E2E",
            border: "1px solid var(--color-border)",
            borderRadius: "var(--radius-sm)",
            display: "flex",
            alignItems: "flex-start",
            gap: "10px",
            fontSize: "12px",
          }}
        >
          <Lock size={16} style={{ color: "var(--color-accent-primary)", marginTop: "2px", flexShrink: 0 }} />
          <div style={{ flex: 1, lineHeight: 1.45 }}>
            <strong style={{ color: "var(--color-text-primary)" }}>DNS Visibility Boundary:</strong>{" "}
            <span style={{ color: "var(--color-text-secondary)" }}>
              SHADOWSENTRY monitors unencrypted port 53 DNS queries. Queries transmitted via DNS-over-HTTPS (DoH),
              DNS-over-TLS (DoT), or private VPN tunnels are encrypted at the transport layer and are not inspected.
              Suspicious indicators use Shannon entropy calculations to identify potential algorithmically generated domains (DGA).
            </span>
          </div>
        </div>

        {/* Filters and Controls */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "10px", flexWrap: "wrap" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            {["ALL", "A", "AAAA", "CNAME", "MX", "TXT", "PTR"].map((type) => {
              const active = selectedRecordType === type;
              return (
                <button
                  key={type}
                  onClick={() => setSelectedRecordType(type)}
                  style={{
                    fontSize: "11px",
                    padding: "3px 8px",
                    backgroundColor: active ? "var(--color-surface-elevated)" : "var(--color-surface)",
                    borderColor: active ? "var(--color-accent-primary)" : "var(--color-border)",
                    color: active ? "var(--color-text-primary)" : "var(--color-text-secondary)",
                    fontWeight: active ? 600 : 400,
                  }}
                >
                  {type}
                </button>
              );
            })}

            <button
              onClick={() => setOnlySuspicious(!onlySuspicious)}
              style={{
                fontSize: "11px",
                padding: "3px 10px",
                backgroundColor: onlySuspicious ? "#2A1810" : "var(--color-surface)",
                borderColor: onlySuspicious ? "var(--color-high)" : "var(--color-border)",
                color: onlySuspicious ? "var(--color-high)" : "var(--color-text-secondary)",
                fontWeight: onlySuspicious ? 600 : 400,
              }}
            >
              <AlertTriangle size={12} />
              <span>Flagged Suspicious ({suspiciousCount})</span>
            </button>
          </div>

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
              placeholder="Search domain name or IP..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{
                paddingLeft: "26px",
                fontSize: "12px",
                height: "28px",
                width: "220px",
              }}
            />
          </div>
        </div>

        {/* DNS Table */}
        <div
          className="table-wrapper"
          tabIndex={0}
          role="region"
          aria-label="DNS query monitor table"
          style={{ flex: 1, minHeight: 0 }}
        >
          <table>
            <thead>
              <tr>
                <th style={{ width: "90px" }}>Time</th>
                <th style={{ width: "65px" }}>Type</th>
                <th>Query Domain Name</th>
                <th style={{ width: "80px" }}>RCODE</th>
                <th style={{ width: "70px" }}>Entropy</th>
                <th>Resolved IP Addresses</th>
                <th style={{ width: "95px" }}>Status</th>
              </tr>
            </thead>
            <tbody>
              {filteredQueries.length === 0 ? (
                <TableEmptyRow
                  colSpan={7}
                  title={isMonitoring ? "Listening for DNS Queries..." : "DNS Monitor Idle"}
                  description={isMonitoring
                    ? "Observing Port 53 UDP/TCP DNS queries on the active interface. Domain resolutions will appear here."
                    : "No DNS activity recorded in the current session. Start monitoring to capture query lookups."}
                  badgeText={isMonitoring ? "Shannon Entropy & DGA Heuristics Active" : "Standby Mode"}
                  iconType={isMonitoring ? "info" : "search"}
                />
              ) : (
                filteredQueries.map((q) => {
                  const isSelected = selectedQuery?.id === q.id;
                  return (
                    <tr
                      key={q.id}
                      onClick={() => setSelectedQuery(q)}
                      className={isSelected ? "selected" : ""}
                      style={{ cursor: "pointer" }}
                    >
                      <td className="font-mono" style={{ color: "var(--color-text-muted)", fontSize: "11px" }}>
                        {formatDateTime(q.timestamp).split(", ")[1] || q.timestamp.substring(11, 19)}
                      </td>
                      <td className="font-mono" style={{ fontWeight: 600, color: "var(--color-accent-secondary)" }}>
                        {q.record_type}
                      </td>
                      <td style={{ fontFamily: "var(--font-mono)", maxWidth: "300px", overflow: "hidden", textOverflow: "ellipsis" }}>
                        {q.query_name}
                      </td>
                      <td className="font-mono" style={{ color: q.response_code === "NXDOMAIN" ? "var(--color-warning)" : "var(--color-text-secondary)" }}>
                        {q.response_code || "PENDING"}
                      </td>
                      <td className="font-mono" style={{ color: q.entropy_score > 3.8 ? "var(--color-high)" : "var(--color-text-muted)" }}>
                        {q.entropy_score.toFixed(2)}
                      </td>
                      <td className="font-mono" style={{ maxWidth: "220px", overflow: "hidden", textOverflow: "ellipsis" }}>
                        {q.resolved_ips.length > 0 ? q.resolved_ips.join(", ") : "—"}
                      </td>
                      <td>
                        {q.is_suspicious ? (
                          <span className="badge" style={{ backgroundColor: "#2A1810", borderColor: "var(--color-high)", color: "var(--color-high)" }}>
                            <AlertTriangle size={10} /> Suspicious
                          </span>
                        ) : (
                          <span className="badge" style={{ backgroundColor: "#10261E", borderColor: "var(--color-success)", color: "var(--color-success)" }}>
                            Normal
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Side Details Panel */}
      {selectedQuery && (
        <aside
          style={{
            width: "380px",
            backgroundColor: "var(--color-surface)",
            borderLeft: "1px solid var(--color-border)",
            display: "flex",
            flexDirection: "column",
            height: "100%",
            overflowY: "auto",
            zIndex: 15,
          }}
        >
          <div
            style={{
              padding: "14px 16px",
              borderBottom: "1px solid var(--color-border)",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              backgroundColor: "var(--color-surface-elevated)",
            }}
          >
            <div>
              <div style={{ fontSize: "13px", fontWeight: 600, color: "var(--color-text-primary)" }}>
                DNS Query Investigation
              </div>
              <div style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>
                Type: {selectedQuery.record_type}
              </div>
            </div>
            <button className="ghost" onClick={() => setSelectedQuery(null)} style={{ padding: "4px" }}>
              ✕
            </button>
          </div>

          <div style={{ padding: "16px", display: "flex", flexDirection: "column", gap: "16px", fontSize: "12px" }}>
            <div>
              <div style={{ fontSize: "10px", color: "var(--color-text-muted)", textTransform: "uppercase", marginBottom: "4px" }}>
                Query Domain
              </div>
              <div style={{ backgroundColor: "var(--color-bg)", padding: "10px", borderRadius: "var(--radius-sm)", border: "1px solid var(--color-border)", fontFamily: "var(--font-mono)", wordBreak: "break-all" }}>
                {selectedQuery.query_name}
              </div>
            </div>

            {selectedQuery.is_suspicious && (
              <div style={{ backgroundColor: "#2A1810", border: "1px solid var(--color-high)", borderRadius: "var(--radius-sm)", padding: "12px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "6px", color: "var(--color-high)", fontWeight: 600, marginBottom: "4px" }}>
                  <AlertTriangle size={14} />
                  <span>Heuristic Alert Flags</span>
                </div>
                <ul style={{ paddingLeft: "16px", color: "var(--color-text-primary)", fontSize: "11px", display: "flex", flexDirection: "column", gap: "4px" }}>
                  {selectedQuery.threat_flags.map((flag, idx) => (
                    <li key={idx}>{flag}</li>
                  ))}
                </ul>
              </div>
            )}

            <div style={{ border: "1px solid var(--color-border)", borderRadius: "var(--radius-sm)", overflow: "hidden" }}>
              <table style={{ width: "100%" }}>
                <tbody>
                  <tr style={{ borderBottom: "1px solid var(--color-border-subtle)" }}>
                    <td style={{ padding: "6px 10px", color: "var(--color-text-muted)", width: "40%", backgroundColor: "var(--color-surface-elevated)" }}>Client IP</td>
                    <td style={{ padding: "6px 10px", fontFamily: "var(--font-mono)" }}>{selectedQuery.client_ip}</td>
                  </tr>
                  <tr style={{ borderBottom: "1px solid var(--color-border-subtle)" }}>
                    <td style={{ padding: "6px 10px", color: "var(--color-text-muted)", backgroundColor: "var(--color-surface-elevated)" }}>Resolver IP</td>
                    <td style={{ padding: "6px 10px", fontFamily: "var(--font-mono)" }}>{selectedQuery.server_ip}</td>
                  </tr>
                  <tr style={{ borderBottom: "1px solid var(--color-border-subtle)" }}>
                    <td style={{ padding: "6px 10px", color: "var(--color-text-muted)", backgroundColor: "var(--color-surface-elevated)" }}>Response Code</td>
                    <td style={{ padding: "6px 10px", fontFamily: "var(--font-mono)" }}>{selectedQuery.response_code || "None (Timeout/Dropped)"}</td>
                  </tr>
                  <tr style={{ borderBottom: "1px solid var(--color-border-subtle)" }}>
                    <td style={{ padding: "6px 10px", color: "var(--color-text-muted)", backgroundColor: "var(--color-surface-elevated)" }}>Shannon Entropy</td>
                    <td style={{ padding: "6px 10px", fontFamily: "var(--font-mono)" }}>{selectedQuery.entropy_score.toFixed(3)}</td>
                  </tr>
                  <tr>
                    <td style={{ padding: "6px 10px", color: "var(--color-text-muted)", backgroundColor: "var(--color-surface-elevated)" }}>Length</td>
                    <td style={{ padding: "6px 10px", fontFamily: "var(--font-mono)" }}>{selectedQuery.query_name.length} characters</td>
                  </tr>
                </tbody>
              </table>
            </div>

            {selectedQuery.resolved_ips.length > 0 && (
              <div>
                <div style={{ fontSize: "11px", color: "var(--color-text-muted)", textTransform: "uppercase", marginBottom: "6px" }}>
                  Resolved IP Addresses ({selectedQuery.resolved_ips.length})
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                  {selectedQuery.resolved_ips.map((ip) => (
                    <div key={ip} style={{ padding: "6px 10px", backgroundColor: "var(--color-bg)", border: "1px solid var(--color-border-subtle)", borderRadius: "var(--radius-sm)", fontFamily: "var(--font-mono)", fontSize: "11px" }}>
                      {ip}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </aside>
      )}
    </div>
  );
};
