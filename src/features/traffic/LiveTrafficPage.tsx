import React, { useState, useMemo } from "react";
import { PacketMetadata, ProtocolType, TrafficDirection } from "../../types/packet";
import { ProtocolBadge } from "../../components/ProtocolBadge";
import { formatBytes, formatTimestamp } from "../../lib/formatters";
import { TableEmptyRow } from "../../components/EmptyState";
import {
  Pause,
  Play,
  RotateCcw,
  Search,
  ArrowDownLeft,
  ArrowUpRight,
  RefreshCw,
  SlidersHorizontal,
  X,
  ShieldAlert,
} from "lucide-react";

interface LiveTrafficPageProps {
  packets: PacketMetadata[];
  isMonitoring: boolean;
  onClearView: () => void;
  onSelectPacket?: (pkt: PacketMetadata) => void;
}

export const LiveTrafficPage: React.FC<LiveTrafficPageProps> = ({
  packets,
  isMonitoring,
  onClearView,
}) => {
  const [isPaused, setIsPaused] = useState(false);
  const [frozenPackets, setFrozenPackets] = useState<PacketMetadata[]>([]);
  const [selectedProtocol, setSelectedProtocol] = useState<string>("ALL");
  const [selectedDirection, setSelectedDirection] = useState<string>("ALL");
  const [searchFilter, setSearchFilter] = useState<string>("");
  const [selectedPacket, setSelectedPacket] = useState<PacketMetadata | null>(null);

  const handleTogglePause = () => {
    if (!isPaused) {
      setFrozenPackets([...packets]);
      setIsPaused(true);
    } else {
      setIsPaused(false);
    }
  };

  const displayedPackets = isPaused ? frozenPackets : packets;

  const filteredPackets = useMemo(() => {
    return displayedPackets.filter((p) => {
      if (selectedProtocol !== "ALL" && p.protocol !== selectedProtocol) {
        return false;
      }
      if (selectedDirection !== "ALL" && p.direction !== selectedDirection) {
        return false;
      }
      if (searchFilter.trim() !== "") {
        const q = searchFilter.toLowerCase();
        const matches =
          p.source_ip.toLowerCase().includes(q) ||
          p.dest_ip.toLowerCase().includes(q) ||
          p.summary.toLowerCase().includes(q) ||
          (p.source_port && p.source_port.toString().includes(q)) ||
          (p.dest_port && p.dest_port.toString().includes(q));
        if (!matches) return false;
      }
      return true;
    });
  }, [displayedPackets, selectedProtocol, selectedDirection, searchFilter]);

  const protocols: { id: string; label: string }[] = [
    { id: "ALL", label: "All Protocols" },
    { id: "TCP", label: "TCP" },
    { id: "UDP", label: "UDP" },
    { id: "DNS", label: "DNS" },
    { id: "ARP", label: "ARP" },
    { id: "ICMP", label: "ICMP" },
  ];

  return (
    <div style={{ display: "flex", height: "100%", width: "100%", overflow: "hidden" }}>
      {/* Main Table Container */}
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
        {/* Top Control Bar */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            flexWrap: "wrap",
            gap: "10px",
          }}
        >
          {/* Protocol Filter Pills */}
          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            {protocols.map((proto) => {
              const active = selectedProtocol === proto.id;
              return (
                <button
                  key={proto.id}
                  onClick={() => setSelectedProtocol(proto.id)}
                  style={{
                    fontSize: "11px",
                    padding: "4px 10px",
                    backgroundColor: active ? "var(--color-surface-elevated)" : "var(--color-surface)",
                    borderColor: active ? "var(--color-accent-primary)" : "var(--color-border)",
                    color: active ? "var(--color-text-primary)" : "var(--color-text-secondary)",
                    fontWeight: active ? 600 : 400,
                  }}
                >
                  {proto.label}
                </button>
              );
            })}
          </div>

          {/* Right Action Controls: Pause, Clear, Search */}
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
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
                placeholder="Search IP, port, summary..."
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                style={{
                  paddingLeft: "26px",
                  fontSize: "12px",
                  height: "28px",
                  width: "180px",
                }}
              />
            </div>

            <button
              onClick={handleTogglePause}
              style={{
                fontSize: "11px",
                padding: "4px 10px",
                backgroundColor: isPaused ? "#28200F" : "var(--color-surface)",
                borderColor: isPaused ? "var(--color-warning)" : "var(--color-border)",
                color: isPaused ? "var(--color-warning)" : "var(--color-text-primary)",
              }}
            >
              {isPaused ? <Play size={12} /> : <Pause size={12} />}
              <span>{isPaused ? "Resume Updates" : "Pause Feed"}</span>
            </button>

            <button
              onClick={onClearView}
              title="Clear visible packets from memory buffer"
              style={{ fontSize: "11px", padding: "4px 10px" }}
            >
              <RotateCcw size={12} />
              <span>Clear View</span>
            </button>
          </div>
        </div>

        {/* Status / Feed Counter Info */}
        <div style={{ display: "flex", justifyContent: "space-between", fontSize: "11px", color: "var(--color-text-muted)" }}>
          <div>
            Showing <strong style={{ color: "var(--color-text-primary)" }}>{filteredPackets.length}</strong> of{" "}
            {displayedPackets.length} recent packets in memory buffer
            {isPaused && <span style={{ color: "var(--color-warning)", marginLeft: "8px" }}>(Feed Paused)</span>}
          </div>
          <div>Metadata-only mode • Raw payloads discarded</div>
        </div>

        {/* Data Table */}
        <div
          className="table-wrapper"
          tabIndex={0}
          role="region"
          aria-label="Network packet traffic table"
          style={{ flex: 1, minHeight: 0 }}
        >
          <table>
            <thead>
              <tr>
                <th style={{ width: "90px" }}>Time</th>
                <th style={{ width: "70px" }}>Proto</th>
                <th>Source Address</th>
                <th style={{ width: "60px" }}>SPort</th>
                <th>Destination Address</th>
                <th style={{ width: "60px" }}>DPort</th>
                <th style={{ width: "65px" }}>Dir</th>
                <th style={{ width: "75px" }}>Size</th>
                <th>Packet Summary</th>
              </tr>
            </thead>
            <tbody>
              {filteredPackets.length === 0 ? (
                <TableEmptyRow
                  colSpan={9}
                  title={isMonitoring ? "Listening for Network Frames..." : "Traffic Ingestion Idle"}
                  description={isMonitoring
                    ? "Observing raw packets on the selected interface. Incoming packets will appear here in real time."
                    : "Packet capture is currently paused. Click 'Start Monitoring' above to begin capturing network frames."}
                  badgeText={isMonitoring ? "Packet Engine Armed & Listening" : "Standby Mode"}
                  iconType={isMonitoring ? "info" : "search"}
                />
              ) : (
                filteredPackets.map((pkt, idx) => {
                  const isSelected = selectedPacket?.id === pkt.id;
                  return (
                    <tr
                      key={pkt.id}
                      onClick={() => setSelectedPacket(pkt)}
                      className={`${isSelected ? "selected" : ""} ${idx < 3 ? "packet-new-row" : ""}`}
                      style={{ cursor: "pointer" }}
                    >
                      <td className="font-mono" style={{ color: "var(--color-text-muted)", fontSize: "11px" }}>
                        {formatTimestamp(pkt.timestamp)}
                      </td>
                      <td>
                        <ProtocolBadge protocol={pkt.protocol} />
                      </td>
                      <td className="font-mono" style={{ fontWeight: 500 }}>
                        {pkt.source_ip}
                      </td>
                      <td className="font-mono" style={{ color: "var(--color-text-secondary)" }}>
                        {pkt.source_port || "—"}
                      </td>
                      <td className="font-mono" style={{ fontWeight: 500 }}>
                        {pkt.dest_ip}
                      </td>
                      <td className="font-mono" style={{ color: "var(--color-text-secondary)" }}>
                        {pkt.dest_port || "—"}
                      </td>
                      <td>
                        <span
                          style={{
                            display: "inline-flex",
                            alignItems: "center",
                            gap: "3px",
                            fontSize: "10px",
                            textTransform: "uppercase",
                            color:
                              pkt.direction === "inbound"
                                ? "var(--color-accent-secondary)"
                                : pkt.direction === "outbound"
                                ? "var(--color-accent-primary)"
                                : "var(--color-text-muted)",
                          }}
                        >
                          {pkt.direction === "inbound" ? (
                            <ArrowDownLeft size={11} />
                          ) : pkt.direction === "outbound" ? (
                            <ArrowUpRight size={11} />
                          ) : null}
                          {pkt.direction}
                        </span>
                      </td>
                      <td className="font-mono" style={{ color: "var(--color-text-secondary)" }}>
                        {pkt.packet_size} B
                      </td>
                      <td style={{ maxWidth: "340px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {pkt.summary}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Slide-out Packet Inspection Details Panel */}
      {selectedPacket && (
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
                Packet Details
              </div>
              <div style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>
                ID: {selectedPacket.id.substring(0, 8)}...
              </div>
            </div>
            <button className="ghost" onClick={() => setSelectedPacket(null)} style={{ padding: "4px" }}>
              <X size={16} />
            </button>
          </div>

          <div style={{ padding: "16px", display: "flex", flexDirection: "column", gap: "16px", fontSize: "12px" }}>
            <div>
              <div style={{ fontSize: "11px", color: "var(--color-text-muted)", textTransform: "uppercase", marginBottom: "4px" }}>
                Summary
              </div>
              <div style={{ backgroundColor: "var(--color-bg)", padding: "8px", borderRadius: "var(--radius-sm)", border: "1px solid var(--color-border-subtle)", fontFamily: "var(--font-mono)" }}>
                {selectedPacket.summary}
              </div>
            </div>

            {/* Protocol & Direction */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
              <div>
                <div style={{ fontSize: "10px", color: "var(--color-text-muted)", textTransform: "uppercase" }}>Protocol</div>
                <div style={{ marginTop: "2px" }}><ProtocolBadge protocol={selectedPacket.protocol} /></div>
              </div>
              <div>
                <div style={{ fontSize: "10px", color: "var(--color-text-muted)", textTransform: "uppercase" }}>Size</div>
                <div style={{ marginTop: "2px", fontFamily: "var(--font-mono)" }}>{selectedPacket.packet_size} bytes</div>
              </div>
            </div>

            {/* Source & Dest info */}
            <div style={{ border: "1px solid var(--color-border)", borderRadius: "var(--radius-sm)", overflow: "hidden" }}>
              <table style={{ width: "100%" }}>
                <tbody>
                  <tr style={{ borderBottom: "1px solid var(--color-border-subtle)" }}>
                    <td style={{ padding: "6px 10px", color: "var(--color-text-muted)", width: "35%", backgroundColor: "var(--color-surface-elevated)" }}>Source IP</td>
                    <td style={{ padding: "6px 10px", fontFamily: "var(--font-mono)" }}>{selectedPacket.source_ip}</td>
                  </tr>
                  <tr style={{ borderBottom: "1px solid var(--color-border-subtle)" }}>
                    <td style={{ padding: "6px 10px", color: "var(--color-text-muted)", backgroundColor: "var(--color-surface-elevated)" }}>Source Port</td>
                    <td style={{ padding: "6px 10px", fontFamily: "var(--font-mono)" }}>{selectedPacket.source_port || "—"}</td>
                  </tr>
                  {selectedPacket.source_mac && (
                    <tr style={{ borderBottom: "1px solid var(--color-border-subtle)" }}>
                      <td style={{ padding: "6px 10px", color: "var(--color-text-muted)", backgroundColor: "var(--color-surface-elevated)" }}>Source MAC</td>
                      <td style={{ padding: "6px 10px", fontFamily: "var(--font-mono)" }}>{selectedPacket.source_mac}</td>
                    </tr>
                  )}
                  <tr style={{ borderBottom: "1px solid var(--color-border-subtle)" }}>
                    <td style={{ padding: "6px 10px", color: "var(--color-text-muted)", backgroundColor: "var(--color-surface-elevated)" }}>Dest IP</td>
                    <td style={{ padding: "6px 10px", fontFamily: "var(--font-mono)" }}>{selectedPacket.dest_ip}</td>
                  </tr>
                  <tr style={{ borderBottom: "1px solid var(--color-border-subtle)" }}>
                    <td style={{ padding: "6px 10px", color: "var(--color-text-muted)", backgroundColor: "var(--color-surface-elevated)" }}>Dest Port</td>
                    <td style={{ padding: "6px 10px", fontFamily: "var(--font-mono)" }}>{selectedPacket.dest_port || "—"}</td>
                  </tr>
                  {selectedPacket.dest_mac && (
                    <tr>
                      <td style={{ padding: "6px 10px", color: "var(--color-text-muted)", backgroundColor: "var(--color-surface-elevated)" }}>Dest MAC</td>
                      <td style={{ padding: "6px 10px", fontFamily: "var(--font-mono)" }}>{selectedPacket.dest_mac}</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {/* TCP Flags */}
            {selectedPacket.tcp_flags && (
              <div>
                <div style={{ fontSize: "11px", color: "var(--color-text-muted)", textTransform: "uppercase", marginBottom: "6px" }}>
                  TCP Flags
                </div>
                <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                  {Object.entries(selectedPacket.tcp_flags).map(([flag, val]) => (
                    <span
                      key={flag}
                      className="badge font-mono"
                      style={{
                        backgroundColor: val ? "var(--color-surface-elevated)" : "var(--color-bg)",
                        borderColor: val ? "var(--color-accent-primary)" : "var(--color-border)",
                        color: val ? "var(--color-text-primary)" : "var(--color-text-muted)",
                        opacity: val ? 1 : 0.5,
                      }}
                    >
                      {flag.toUpperCase()}: {val ? "1" : "0"}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* DNS Data if present */}
            {selectedPacket.dns_data && (
              <div>
                <div style={{ fontSize: "11px", color: "var(--color-accent-secondary)", textTransform: "uppercase", fontWeight: 600, marginBottom: "6px" }}>
                  DNS Payload Metadata
                </div>
                <div style={{ backgroundColor: "var(--color-bg)", padding: "10px", borderRadius: "var(--radius-sm)", border: "1px solid var(--color-border-subtle)" }}>
                  <div><strong>Query:</strong> <span className="font-mono">{selectedPacket.dns_data.query_name}</span></div>
                  <div><strong>Type:</strong> <span className="font-mono">{selectedPacket.dns_data.query_type}</span></div>
                  {selectedPacket.dns_data.response_code && (
                    <div><strong>RCODE:</strong> <span className="font-mono">{selectedPacket.dns_data.response_code}</span></div>
                  )}
                  {selectedPacket.dns_data.resolved_ips.length > 0 && (
                    <div><strong>Answers:</strong> {selectedPacket.dns_data.resolved_ips.join(", ")}</div>
                  )}
                </div>
              </div>
            )}

            <div style={{ fontSize: "11px", color: "var(--color-text-muted)", borderTop: "1px solid var(--color-border)", paddingTop: "12px" }}>
              Observed on network interface: <strong>{selectedPacket.interface_name}</strong>
            </div>
          </div>
        </aside>
      )}
    </div>
  );
};
