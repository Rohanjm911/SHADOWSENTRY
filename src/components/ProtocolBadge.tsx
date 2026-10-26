import React from "react";
import { ProtocolType } from "../types/packet";

interface ProtocolBadgeProps {
  protocol: ProtocolType;
}

export const ProtocolBadge: React.FC<ProtocolBadgeProps> = ({ protocol }) => {
  const config = {
    TCP: { bg: "#101D2E", border: "#4C8DFF", text: "#4C8DFF" },
    UDP: { bg: "#0F242A", border: "#45C6D8", text: "#45C6D8" },
    DNS: { bg: "#231834", border: "#B47EFF", text: "#B47EFF" },
    ARP: { bg: "#10261E", border: "#35C98A", text: "#35C98A" },
    ICMP: { bg: "#2B2110", border: "#F4B942", text: "#F4B942" },
    "IPv6-ICMP": { bg: "#2B2110", border: "#F4B942", text: "#F4B942" },
    OTHER: { bg: "#151D27", border: "#6C7A8E", text: "#A8B3C2" },
  }[protocol] || { bg: "#151D27", border: "#6C7A8E", text: "#A8B3C2" };

  return (
    <span
      className="badge font-mono"
      style={{
        backgroundColor: config.bg,
        borderColor: config.border,
        color: config.text,
      }}
    >
      {protocol}
    </span>
  );
};
