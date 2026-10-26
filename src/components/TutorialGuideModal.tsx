import React, { useState } from "react";
import {
  HelpCircle,
  X,
  ArrowRight,
  ArrowLeft,
  Activity,
  Globe,
  ShieldAlert,
  FlaskConical,
  FileText,
  Settings,
  Play,
  CheckCircle2,
  Zap,
  HardDrive,
  ShieldCheck,
  Radio,
  Search,
  ExternalLink,
} from "lucide-react";
import { NavTab } from "./AppSidebar";

interface TutorialGuideModalProps {
  isOpen: boolean;
  onClose: () => void;
  onNavigateTab: (tab: NavTab) => void;
}

interface TutorialSection {
  id: string;
  tabTarget?: NavTab;
  title: string;
  shortLabel: string;
  icon: React.ElementType;
  badge: string;
  badgeColor: string;
  headline: string;
  description: string;
  keyPoints: { label: string; text: string }[];
  uiMockup: React.ReactNode;
}

export const TutorialGuideModal: React.FC<TutorialGuideModalProps> = ({
  isOpen,
  onClose,
  onNavigateTab,
}) => {
  const [activeStepIndex, setActiveStepIndex] = useState(0);

  if (!isOpen) return null;

  const sections: TutorialSection[] = [
    {
      id: "quickstart",
      tabTarget: "dashboard",
      title: "Quick Start & Packet Capture Modes",
      shortLabel: "1. Quick Start",
      icon: Play,
      badge: "Foundation",
      badgeColor: "var(--color-accent-primary)",
      headline: "Starting wire-speed network packet inspection safely on Windows",
      description:
        "SHADOWSENTRY monitors host network traffic using a multi-tiered ingestion engine with zero cloud dependencies. Choose your network adapter and click 'Start Monitoring' to begin.",
      keyPoints: [
        {
          label: "Windows Raw Sockets (Mode 1)",
          text: "Requires running as Administrator. Captures all live host IPv4, TCP, UDP, and DNS traffic with zero driver installation.",
        },
        {
          label: "Npcap Promiscuous Sniffer (Mode 2)",
          text: "When Npcap is installed, captures full Layer-2 Ethernet frames, ARP poisoning anomalies, and raw MAC mappings.",
        },
        {
          label: "Lab Synthetic Mode (Mode 3)",
          text: "Works as a standard user without elevation. Runs realistic security scenarios (port scans, DGAs, gateway changes) for offline testing.",
        },
      ],
      uiMockup: (
        <div style={{ backgroundColor: "#060A12", border: "1px solid var(--color-border)", borderRadius: "var(--radius-sm)", padding: "12px", fontFamily: "var(--font-mono)", fontSize: "11px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid var(--color-border-subtle)", paddingBottom: "8px", marginBottom: "8px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <span style={{ width: 8, height: 8, borderRadius: "50%", backgroundColor: "var(--color-success)" }} />
              <span style={{ color: "var(--color-text-primary)", fontWeight: 600 }}>Interface: Wi-Fi (192.168.1.105)</span>
            </div>
            <span style={{ backgroundColor: "rgba(56, 189, 248, 0.15)", color: "var(--color-accent-primary)", padding: "2px 6px", borderRadius: "3px" }}>
              Raw Sockets // Active
            </span>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "8px", textAlign: "center" }}>
            <div style={{ backgroundColor: "#0E1726", padding: "6px", borderRadius: "3px" }}>
              <div style={{ color: "var(--color-text-muted)", fontSize: "10px" }}>PACKET RATE</div>
              <div style={{ color: "var(--color-success)", fontWeight: 700, fontSize: "13px" }}>142 pkts/s</div>
            </div>
            <div style={{ backgroundColor: "#0E1726", padding: "6px", borderRadius: "3px" }}>
              <div style={{ color: "var(--color-text-muted)", fontSize: "10px" }}>THREAT RULES</div>
              <div style={{ color: "var(--color-accent-primary)", fontWeight: 700, fontSize: "13px" }}>10 Armed</div>
            </div>
            <div style={{ backgroundColor: "#0E1726", padding: "6px", borderRadius: "3px" }}>
              <div style={{ color: "var(--color-text-muted)", fontSize: "10px" }}>PRIVACY</div>
              <div style={{ color: "var(--color-text-primary)", fontWeight: 700, fontSize: "13px" }}>100% Offline</div>
            </div>
          </div>
        </div>
      ),
    },
    {
      id: "traffic",
      tabTarget: "traffic",
      title: "Live Traffic & Protocol Inspection",
      shortLabel: "2. Live Traffic",
      icon: Activity,
      badge: "Wire Analysis",
      badgeColor: "#38BDF8",
      headline: "Streaming wire-level packet table with real-time protocol breakdown",
      description:
        "The Live Traffic workspace renders packets as they cross the network adapter. Filter by protocol, search by IP/port, and inspect truncated raw payloads.",
      keyPoints: [
        {
          label: "Protocol Filtering",
          text: "Quick-toggle filters for TCP (Blue), UDP (Cyan), DNS (Purple), ARP (Green), and ICMP (Yellow).",
        },
        {
          label: "Hex & ASCII Inspector",
          text: "Click any packet row to inspect Layer 2-4 headers and decoded wire payload safely.",
        },
        {
          label: "High-Density Compact Mode",
          text: "Press Alt+D anytime to toggle high-density compact table view to observe hundreds of packets per screen.",
        },
      ],
      uiMockup: (
        <div style={{ backgroundColor: "#060A12", border: "1px solid var(--color-border)", borderRadius: "var(--radius-sm)", overflow: "hidden", fontFamily: "var(--font-mono)", fontSize: "11px" }}>
          <div style={{ backgroundColor: "#0E1726", padding: "6px 10px", display: "flex", gap: "12px", borderBottom: "1px solid var(--color-border-subtle)", color: "var(--color-text-muted)" }}>
            <span style={{ width: "70px" }}>TIME</span>
            <span style={{ width: "50px" }}>PROTO</span>
            <span style={{ width: "140px" }}>SOURCE</span>
            <span style={{ width: "140px" }}>DESTINATION</span>
            <span>SUMMARY</span>
          </div>
          <div style={{ padding: "6px 10px", display: "flex", gap: "12px", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
            <span style={{ width: "70px", color: "var(--color-text-muted)" }}>01:23:45</span>
            <span style={{ width: "50px", color: "#38BDF8", fontWeight: 700 }}>TCP</span>
            <span style={{ width: "140px" }}>192.168.1.105:54321</span>
            <span style={{ width: "140px" }}>142.250.190.46:443</span>
            <span style={{ color: "var(--color-text-secondary)" }}>TLS Client Hello (SNI)</span>
          </div>
          <div style={{ padding: "6px 10px", display: "flex", gap: "12px", backgroundColor: "rgba(180, 126, 255, 0.08)" }}>
            <span style={{ width: "70px", color: "var(--color-text-muted)" }}>01:23:46</span>
            <span style={{ width: "50px", color: "#B47EFF", fontWeight: 700 }}>DNS</span>
            <span style={{ width: "140px" }}>192.168.1.105:61234</span>
            <span style={{ width: "140px" }}>1.1.1.1:53</span>
            <span style={{ color: "#B47EFF" }}>Query A api.github.com</span>
          </div>
        </div>
      ),
    },
    {
      id: "threats",
      tabTarget: "threats",
      title: "Threat Center & 10 Explainable Rules",
      shortLabel: "3. Threat Center",
      icon: ShieldAlert,
      badge: "Detection",
      badgeColor: "var(--color-critical)",
      headline: "100% deterministic detection with actionable triage guidance",
      description:
        "SHADOWSENTRY rejects opaque 'AI confidence scores'. Every alert is triggered by strict, evidence-backed network heuristics and provides an investigation checklist.",
      keyPoints: [
        {
          label: "Rule 1: Reconnaissance Scan",
          text: "Detects multi-port sweeps probing 15 or more target ports from a single IP within 10 seconds.",
        },
        {
          label: "Rule 5 & 6: Gateway & ARP Spoofer",
          text: "Detects when the default gateway MAC changes or when multiple MACs claim the same subnet IP (Man-in-the-Middle).",
        },
        {
          label: "Slide-Out Forensic Panel",
          text: "Click any alert to open the forensic triage panel detailing why it fired, uncertainty factors, and recommended remediation.",
        },
      ],
      uiMockup: (
        <div style={{ backgroundColor: "#060A12", border: "1px solid var(--color-critical)", borderRadius: "var(--radius-sm)", padding: "10px", fontFamily: "var(--font-mono)", fontSize: "11px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "6px" }}>
            <span style={{ backgroundColor: "rgba(244, 63, 94, 0.2)", color: "var(--color-critical)", padding: "2px 6px", borderRadius: "3px", fontWeight: 700 }}>
              CRITICAL // RULE-01-PORT-SCAN
            </span>
            <span style={{ color: "var(--color-text-muted)" }}>Observed 18 ports in 4.2s</span>
          </div>
          <div style={{ color: "var(--color-text-primary)", fontWeight: 600, marginBottom: "4px" }}>
            Multi-Port Horizontal Sweep from 192.168.1.88
          </div>
          <div style={{ color: "var(--color-text-muted)", fontSize: "10.5px" }}>
            Targeting host sensitive ports: 21, 22, 23, 80, 443, 445, 3389, 8080...
          </div>
        </div>
      ),
    },
    {
      id: "dns",
      tabTarget: "dns",
      title: "DNS Monitor & Shannon Entropy (DGA)",
      shortLabel: "4. DNS & DGAs",
      icon: Globe,
      badge: "Intelligence",
      badgeColor: "#B47EFF",
      headline: "Detecting domain generation algorithms and malicious tunneling",
      description:
        "Monitors all outgoing DNS questions and calculates the Shannon entropy math score of each domain label to spot automated botnet C2 channels.",
      keyPoints: [
        {
          label: "Shannon Entropy Scoring",
          text: "Human-readable domains have low entropy (e.g. google.com: ~2.1). Random algorithmically generated domains score > 3.8.",
        },
        {
          label: "Long Query Detection",
          text: "Flags queries exceeding 45 characters, which often indicates base64 data exfiltration over DNS tunnels.",
        },
        {
          label: "Query Breakdown",
          text: "Categorizes records by type (A, AAAA, CNAME, TXT, MX) and flags suspicious top-level domains.",
        },
      ],
      uiMockup: (
        <div style={{ backgroundColor: "#060A12", border: "1px solid var(--color-border)", borderRadius: "var(--radius-sm)", padding: "10px", fontFamily: "var(--font-mono)", fontSize: "11px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
            <span style={{ color: "var(--color-text-primary)", fontWeight: 600 }}>x9q2jklms048bf82.biz</span>
            <span style={{ color: "var(--color-critical)", backgroundColor: "rgba(244, 63, 94, 0.15)", padding: "2px 6px", borderRadius: "3px", fontWeight: 700 }}>
              Entropy: 4.21 (High Risk DGA)
            </span>
          </div>
          <div style={{ height: "4px", backgroundColor: "#1E293B", borderRadius: "2px", overflow: "hidden" }}>
            <div style={{ width: "88%", height: "100%", backgroundColor: "var(--color-critical)" }} />
          </div>
        </div>
      ),
    },
    {
      id: "honeypot",
      tabTarget: "honeypot",
      title: "Honeypot Deception Lab",
      shortLabel: "5. Honeypot Lab",
      icon: FlaskConical,
      badge: "Deception",
      badgeColor: "var(--color-warning)",
      headline: "Controlled loopback decoy services to trap reconnaissance probes",
      description:
        "The Honeypot Lab lets you deploy simulated decoys on your machine. Any unauthorized connection directly triggers Rule 8 with forensic evidence.",
      keyPoints: [
        {
          label: "HTTP Decoy Server (:8088)",
          text: "Simulates an exposed web server. Traps automated vulnerability scanners probing for /.env, /admin, and API endpoints.",
        },
        {
          label: "Admin Portal Decoy (:8443)",
          text: "Simulates internal corporate Single Sign-On router dashboard. Safely captures credential spraying attempts.",
        },
        {
          label: "1-Click Attack Simulator",
          text: "Use the built-in 'Run Probe Now' buttons to fire test requests from inside the app and see Rule 8 trigger live!",
        },
      ],
      uiMockup: (
        <div style={{ backgroundColor: "#060A12", border: "1px solid var(--color-warning)", borderRadius: "var(--radius-sm)", padding: "10px", fontFamily: "var(--font-mono)", fontSize: "11px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
              <span style={{ width: 7, height: 7, borderRadius: "50%", backgroundColor: "var(--color-success)" }} />
              <strong style={{ color: "var(--color-text-primary)" }}>HTTP Decoy Server (:8088)</strong>
            </div>
            <span style={{ color: "var(--color-success)", fontWeight: 700 }}>ARMED & LISTENING</span>
          </div>
          <div style={{ backgroundColor: "#0A1322", padding: "6px 8px", borderRadius: "3px", color: "var(--color-text-secondary)", fontSize: "10.5px", marginBottom: "6px" }}>
            Quick Test: <code>curl http://127.0.0.1:8088/.env</code>
          </div>
          <div style={{ display: "flex", gap: "6px" }}>
            <span style={{ backgroundColor: "rgba(56, 189, 248, 0.15)", color: "var(--color-accent-primary)", padding: "2px 6px", borderRadius: "3px", fontSize: "10px" }}>
              ⚡ 1-Click Probe Ready
            </span>
            <span style={{ backgroundColor: "rgba(52, 211, 153, 0.15)", color: "var(--color-success)", padding: "2px 6px", borderRadius: "3px", fontSize: "10px" }}>
              Loopback 127.0.0.1 (Safe)
            </span>
          </div>
        </div>
      ),
    },
    {
      id: "forensics",
      tabTarget: "reports",
      title: "Forensics, Reports & Privacy Controls",
      shortLabel: "6. Reports & Privacy",
      icon: FileText,
      badge: "Privacy First",
      badgeColor: "var(--color-success)",
      headline: "Local-first forensic export and cryptographic database management",
      description:
        "All telemetry remains strictly on host NVMe storage. Generate sanitized forensic audit summaries or cryptographically erase local records at any time.",
      keyPoints: [
        {
          label: "Sanitized CSV & JSON Export",
          text: "Exports events and session timelines while scrubbing raw personal payloads and internal operating system paths.",
        },
        {
          label: "One-Click Database Purge",
          text: "Wipes historical records and executes SQLite VACUUM to reclaim storage and preserve local device privacy.",
        },
        {
          label: "Zero Cloud Telemetry",
          text: "No metrics, logs, or crash dumps are ever transmitted externally. True offline-first forensic design.",
        },
      ],
      uiMockup: (
        <div style={{ backgroundColor: "#060A12", border: "1px solid var(--color-border)", borderRadius: "var(--radius-sm)", padding: "10px", fontFamily: "var(--font-mono)", fontSize: "11px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
            <span style={{ color: "var(--color-success)", fontWeight: 700 }}>SQLITE 3 FORENSIC ARCHIVE</span>
            <span style={{ color: "var(--color-text-muted)" }}>WAL Mode Active</span>
          </div>
          <div style={{ display: "flex", gap: "8px" }}>
            <button className="ghost" style={{ flex: 1, padding: "5px", fontSize: "10.5px", border: "1px solid var(--color-border)" }}>
              Export Sanitized JSON
            </button>
            <button className="ghost" style={{ flex: 1, padding: "5px", fontSize: "10.5px", border: "1px solid var(--color-border)" }}>
              Export Forensic CSV
            </button>
          </div>
        </div>
      ),
    },
  ];

  const currentSection = sections[activeStepIndex];

  const handleJumpToTab = (tab?: NavTab) => {
    if (tab) {
      onNavigateTab(tab);
      onClose();
    }
  };

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 9999,
        backgroundColor: "rgba(6, 10, 18, 0.85)",
        backdropFilter: "blur(12px)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: "20px",
        userSelect: "none",
        animation: "appSmoothEntrance 0.25s cubic-bezier(0.16, 1, 0.3, 1) forwards",
      }}
    >
      {/* Modal Dialog Card */}
      <div
        style={{
          width: "920px",
          maxWidth: "96vw",
          maxHeight: "88vh",
          backgroundColor: "#0D1522",
          border: "1px solid var(--color-border)",
          borderRadius: "var(--radius-lg)",
          boxShadow: "0 28px 70px rgba(0, 0, 0, 0.75), 0 0 0 1px rgba(56, 189, 248, 0.15)",
          display: "flex",
          flexDirection: "column",
          overflow: "hidden",
        }}
      >
        {/* Header */}
        <div
          style={{
            padding: "16px 20px",
            borderBottom: "1px solid var(--color-border)",
            backgroundColor: "#09101B",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            <div
              style={{
                width: "36px",
                height: "36px",
                borderRadius: "var(--radius-sm)",
                backgroundColor: "rgba(56, 189, 248, 0.12)",
                border: "1px solid var(--color-accent-primary)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "var(--color-accent-primary)",
              }}
            >
              <HelpCircle size={20} />
            </div>
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <h2 style={{ fontSize: "16px", fontWeight: 700, color: "var(--color-text-primary)", margin: 0 }}>
                  SHADOWSENTRY — Interactive User Guide & Walkthrough
                </h2>
                <span
                  style={{
                    fontSize: "10px",
                    fontWeight: 700,
                    padding: "2px 6px",
                    borderRadius: "4px",
                    backgroundColor: "rgba(52, 211, 153, 0.15)",
                    color: "var(--color-success)",
                    border: "1px solid rgba(52, 211, 153, 0.3)",
                  }}
                >
                  Step {activeStepIndex + 1} of {sections.length}
                </span>
              </div>
              <p style={{ fontSize: "11.5px", color: "var(--color-text-muted)", margin: "2px 0 0 0" }}>
                Learn how to monitor traffic, triage explainable threats, and test honeypots safely
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="ghost"
            style={{
              padding: "6px",
              color: "var(--color-text-muted)",
              cursor: "pointer",
            }}
            title="Close Tutorial (Esc)"
          >
            <X size={18} />
          </button>
        </div>

        {/* Modal Body: Left Tab Sidebar + Right Content Area */}
        <div style={{ display: "flex", flex: 1, minHeight: "440px", overflow: "hidden" }}>
          {/* Left Step Navigation */}
          <div
            style={{
              width: "230px",
              backgroundColor: "#080D16",
              borderRight: "1px solid var(--color-border)",
              padding: "12px 8px",
              display: "flex",
              flexDirection: "column",
              gap: "4px",
              flexShrink: 0,
            }}
          >
            <div style={{ fontSize: "10px", fontWeight: 700, color: "var(--color-text-muted)", textTransform: "uppercase", padding: "4px 8px 6px 8px", letterSpacing: "0.08em" }}>
              Tutorial Modules:
            </div>
            {sections.map((sec, idx) => {
              const isActive = idx === activeStepIndex;
              const Icon = sec.icon;

              return (
                <button
                  key={sec.id}
                  onClick={() => setActiveStepIndex(idx)}
                  style={{
                    width: "100%",
                    display: "flex",
                    alignItems: "center",
                    gap: "9px",
                    padding: "9px 10px",
                    borderRadius: "var(--radius-sm)",
                    backgroundColor: isActive ? "rgba(56, 189, 248, 0.14)" : "transparent",
                    border: `1px solid ${isActive ? "var(--color-accent-primary)" : "transparent"}`,
                    color: isActive ? "var(--color-text-primary)" : "var(--color-text-secondary)",
                    fontWeight: isActive ? 600 : 400,
                    textAlign: "left",
                    fontSize: "12px",
                    transition: "all 0.15s ease",
                  }}
                >
                  <Icon size={15} style={{ color: isActive ? "var(--color-accent-primary)" : "var(--color-text-muted)" }} />
                  <span style={{ flex: 1 }}>{sec.shortLabel}</span>
                  {isActive && <span style={{ width: 5, height: 5, borderRadius: "50%", backgroundColor: "var(--color-accent-primary)" }} />}
                </button>
              );
            })}
          </div>

          {/* Right Main Detail Area */}
          <div
            style={{
              flex: 1,
              padding: "20px 24px",
              overflowY: "auto",
              display: "flex",
              flexDirection: "column",
              justifyContent: "space-between",
              gap: "16px",
            }}
          >
            <div>
              {/* Badge & Title */}
              <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
                <span
                  style={{
                    fontSize: "10px",
                    fontFamily: "var(--font-mono)",
                    fontWeight: 700,
                    padding: "2px 8px",
                    borderRadius: "4px",
                    backgroundColor: "rgba(255, 255, 255, 0.06)",
                    color: currentSection.badgeColor,
                    border: `1px solid ${currentSection.badgeColor}`,
                  }}
                >
                  {currentSection.badge}
                </span>
                <span style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>
                  Module Guide
                </span>
              </div>

              <h3 style={{ fontSize: "18px", fontWeight: 700, color: "var(--color-text-primary)", margin: "0 0 6px 0" }}>
                {currentSection.title}
              </h3>

              <p style={{ fontSize: "12.5px", color: "var(--color-text-secondary)", lineHeight: 1.5, margin: "0 0 14px 0" }}>
                {currentSection.description}
              </p>

              {/* UI Screenshot / Preview Box */}
              <div style={{ marginBottom: "16px" }}>
                <div style={{ fontSize: "10.5px", fontWeight: 700, color: "var(--color-text-muted)", textTransform: "uppercase", marginBottom: "6px", letterSpacing: "0.06em" }}>
                  Interface Preview & Controls:
                </div>
                {currentSection.uiMockup}
              </div>

              {/* Key Walkthrough Points */}
              <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                {currentSection.keyPoints.map((pt, i) => (
                  <div
                    key={i}
                    style={{
                      display: "flex",
                      alignItems: "flex-start",
                      gap: "8px",
                      padding: "8px 10px",
                      backgroundColor: "rgba(15, 23, 42, 0.5)",
                      borderRadius: "var(--radius-sm)",
                      border: "1px solid var(--color-border-subtle)",
                      fontSize: "12px",
                      lineHeight: 1.45,
                    }}
                  >
                    <CheckCircle2 size={15} style={{ color: "var(--color-success)", marginTop: "2px", flexShrink: 0 }} />
                    <div>
                      <strong style={{ color: "var(--color-text-primary)" }}>{pt.label}:</strong>{" "}
                      <span style={{ color: "var(--color-text-secondary)" }}>{pt.text}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Bottom Actions */}
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                borderTop: "1px solid var(--color-border)",
                paddingTop: "14px",
                marginTop: "10px",
              }}
            >
              <div style={{ display: "flex", gap: "8px" }}>
                <button
                  className="ghost"
                  disabled={activeStepIndex === 0}
                  onClick={() => setActiveStepIndex((prev) => Math.max(0, prev - 1))}
                  style={{ fontSize: "12px", padding: "6px 12px", display: "flex", alignItems: "center", gap: "6px" }}
                >
                  <ArrowLeft size={14} />
                  <span>Previous</span>
                </button>
                <button
                  className="ghost"
                  disabled={activeStepIndex === sections.length - 1}
                  onClick={() => setActiveStepIndex((prev) => Math.min(sections.length - 1, prev + 1))}
                  style={{ fontSize: "12px", padding: "6px 12px", display: "flex", alignItems: "center", gap: "6px" }}
                >
                  <span>Next Step</span>
                  <ArrowRight size={14} />
                </button>
              </div>

              {currentSection.tabTarget && (
                <button
                  className="primary"
                  onClick={() => handleJumpToTab(currentSection.tabTarget)}
                  style={{ fontSize: "12px", padding: "6px 14px", display: "flex", alignItems: "center", gap: "6px", fontWeight: 600 }}
                >
                  <span>Open This Tab in App</span>
                  <ExternalLink size={13} />
                </button>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
