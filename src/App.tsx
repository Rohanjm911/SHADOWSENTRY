import React, { useState, useEffect, useCallback } from "react";
import { AppSidebar, NavTab } from "./components/AppSidebar";
import { TopStatusBar } from "./components/TopStatusBar";
import { BottomStatusBar } from "./components/BottomStatusBar";
import { EventDetailsPanel } from "./components/EventDetailsPanel";
import { DashboardPage } from "./features/dashboard/DashboardPage";
import { LiveTrafficPage } from "./features/traffic/LiveTrafficPage";
import { DnsMonitorPage } from "./features/dns/DnsMonitorPage";
import { ThreatCenterPage } from "./features/threats/ThreatCenterPage";
import { HoneypotLabPage } from "./features/honeypot/HoneypotLabPage";
import { EventHistoryPage } from "./features/events/EventHistoryPage";
import { ReportsPage } from "./features/reports/ReportsPage";
import { SettingsPage } from "./features/settings/SettingsPage";
import { StartupDiagnosticScreen } from "./components/StartupDiagnosticScreen";
import { TutorialGuideModal } from "./components/TutorialGuideModal";
import { soundEffects } from "./lib/soundEffects";

import {
  NetworkInterfaceInfo,
  DriverStatus,
  MonitoringStatus,
  GatewayInfo,
  CaptureBackendType,
} from "./types/network";
import { PacketMetadata, DnsQueryRecord } from "./types/packet";
import { SecurityEvent, EventStatus } from "./types/event";
import { HoneypotServiceState, HoneypotInteractionLog } from "./types/honeypot";
import { SessionStats, ProtocolMetric, TrafficTimelinePoint, SeverityDistribution } from "./types/stats";
import { AppSettings } from "./types/settings";

import * as api from "./lib/tauri";

export const App: React.FC = () => {
  const urlParams = typeof window !== "undefined" ? new URLSearchParams(window.location.search) : null;
  const [showStartup, setShowStartup] = useState<boolean>(() => !urlParams?.has("skipIntro"));
  const [splashFading, setSplashFading] = useState<boolean>(false);
  const [showTutorial, setShowTutorial] = useState<boolean>(() => urlParams?.get("tutorial") === "true");
  const [isMuted, setIsMuted] = useState<boolean>(() => soundEffects.isMuted());
  const [currentTheme, setCurrentTheme] = useState<string>(() => {
    return localStorage.getItem("shadowsentry_theme") || "nordic-slate";
  });
  const [activeTab, setActiveTab] = useState<NavTab>(() => (urlParams?.get("tab") as NavTab) || "dashboard");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  const prevEventsCountRef = React.useRef<number | null>(null);
  const prevHoneypotCountRef = React.useRef<number | null>(null);

  // Synchronize audio mute state across components
  useEffect(() => {
    return soundEffects.subscribe((muted) => setIsMuted(muted));
  }, []);

  const handleSelectTheme = (theme: string) => {
    setCurrentTheme(theme);
    localStorage.setItem("shadowsentry_theme", theme);
    document.documentElement.setAttribute("data-theme", theme);
    soundEffects.playToggle();
  };

  // Core State
  const [interfaces, setInterfaces] = useState<NetworkInterfaceInfo[]>([]);
  const [selectedInterface, setSelectedInterface] = useState<string | null>(null);
  const [driverStatus, setDriverStatus] = useState<DriverStatus>({
    npcap_installed: false,
    npcap_version: null,
    npcap_service_running: false,
    is_elevated_admin: false,
    raw_sockets_supported: false,
    supported_backends: ["raw_socket", "iphelper", "lab_synthetic"],
    recommended_backend: "raw_socket",
    diagnostic_notes: [],
  });
  const [monitoringStatus, setMonitoringStatus] = useState<MonitoringStatus>({
    is_active: false,
    active_backend: null,
    selected_interface: null,
    session_id: null,
    start_time: null,
    duration_seconds: 0,
    packet_count: 0,
    byte_count: 0,
    event_count: 0,
    is_paused: false,
    metadata_only_mode: true,
    error_message: null,
  });
  const [gatewayInfo, setGatewayInfo] = useState<GatewayInfo>({
    ip_address: "192.168.1.1",
    mac_address: "70:4F:57:A2:BB:01",
    interface_name: "Default Network",
    interface_index: 1,
    metric: 25,
    is_reachable: true,
    last_observed: new Date().toISOString(),
    consecutive_changes: 0,
  });

  const [livePackets, setLivePackets] = useState<PacketMetadata[]>([]);
  const [dnsQueries, setDnsQueries] = useState<DnsQueryRecord[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [honeypotServices, setHoneypotServices] = useState<HoneypotServiceState[]>([]);
  const [honeypotLogs, setHoneypotLogs] = useState<HoneypotInteractionLog[]>([]);

  const [sessionStats, setSessionStats] = useState<SessionStats>({
    session_id: "sess-idle",
    start_time: new Date().toISOString(),
    duration_seconds: 0,
    total_packets: 0,
    total_bytes: 0,
    active_connections: 0,
    security_findings_total: 0,
    dns_queries_total: 0,
    honeypot_probes_total: 0,
    capture_backend: "Standby",
    interface_name: "None selected",
    packet_rate_per_sec: 0,
    byte_rate_per_sec: 0,
  });

  const [protocolMetrics, setProtocolMetrics] = useState<ProtocolMetric[]>([
    { protocol: "TCP", packet_count: 0, byte_count: 0, percentage: 0, color: "#4C8DFF" },
    { protocol: "UDP", packet_count: 0, byte_count: 0, percentage: 0, color: "#45C6D8" },
    { protocol: "DNS", packet_count: 0, byte_count: 0, percentage: 0, color: "#B47EFF" },
    { protocol: "ARP", packet_count: 0, byte_count: 0, percentage: 0, color: "#35C98A" },
    { protocol: "ICMP", packet_count: 0, byte_count: 0, percentage: 0, color: "#F4B942" },
  ]);

  const [trafficTimeline, setTrafficTimeline] = useState<TrafficTimelinePoint[]>([]);
  const [severityDist, setSeverityDist] = useState<SeverityDistribution>({
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
  });

  const [settings, setSettings] = useState<AppSettings>({
    theme: "dark",
    preferred_interface: null,
    preferred_backend: "raw_socket",
    notifications_enabled: true,
    launch_at_startup: false,
    privacy: {
      retention_days: 14,
      payload_capture_enabled: false,
      redact_sensitive_local_ips: false,
      telemetry_enabled: false,
      bounded_log_size_mb: 250,
    },
    thresholds: {
      port_scan_count: 15,
      port_scan_window_secs: 10,
      burst_packet_rate: 1000,
      burst_window_secs: 5,
      failed_conn_count: 20,
      failed_conn_window_secs: 10,
      dns_entropy_min: 3.8,
      dns_max_name_length: 55,
      inbound_probe_threshold: 10,
    },
  });

  // Table & Layout Density State (Standard vs Compact)
  const [isCompact, setIsCompact] = useState<boolean>(() => {
    return localStorage.getItem("shadowsentry_density") === "compact";
  });

  // Synchronize density mode with root DOM
  useEffect(() => {
    document.documentElement.setAttribute("data-density", isCompact ? "compact" : "standard");
    localStorage.setItem("shadowsentry_density", isCompact ? "compact" : "standard");
  }, [isCompact]);

  // Initial Load
  useEffect(() => {
    async function init() {
      try {
        const [ifaces, dStatus, mStatus, gw, sets, hServices, evts] = await Promise.all([
          api.getNetworkInterfaces(),
          api.getCaptureDriverStatus(),
          api.getMonitoringStatus(),
          api.getGatewayInfo(),
          api.getAppSettings(),
          api.getHoneypotStatus(),
          api.getSecurityEvents(),
        ]);

        setInterfaces(ifaces);
        if (ifaces.length > 0) {
          const defaultIface = ifaces.find((i) => i.is_up && !i.is_loopback) || ifaces[0];
          setSelectedInterface(defaultIface.friendly_name);
        }
        setDriverStatus(dStatus);
        setMonitoringStatus(mStatus);
        setGatewayInfo(gw);
        setSettings(sets);
        const activeT = localStorage.getItem("shadowsentry_theme") || sets.theme || "nordic-slate";
        document.documentElement.setAttribute("data-theme", activeT);
        setCurrentTheme(activeT);
        setHoneypotServices(hServices);
        setEvents(evts);
      } catch (err) {
        console.error("Initialization error:", err);
      }
    }
    init();
  }, []);

  // Synchronize theme with DOM
  useEffect(() => {
    document.documentElement.setAttribute("data-theme", currentTheme);
  }, [currentTheme]);

  const handleNavigate = (tab: NavTab) => {
    soundEffects.playNavClick();
    setActiveTab(tab);
    setSelectedEvent(null);
  };

  const handleToggleDensity = () => {
    soundEffects.playToggle();
    setIsCompact((prev) => !prev);
  };

  // Global Desktop Keyboard Shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Escape closes slide-out panel
      if (e.key === "Escape" && selectedEvent) {
        setSelectedEvent(null);
        return;
      }

      // Alt + D: Toggle High-Density Compact View
      if (e.altKey && (e.key === "d" || e.key === "D")) {
        e.preventDefault();
        handleToggleDensity();
        return;
      }

      // Ctrl + Number navigation
      if ((e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey) {
        switch (e.key) {
          case "1":
            e.preventDefault();
            handleNavigate("dashboard");
            break;
          case "2":
            e.preventDefault();
            handleNavigate("traffic");
            break;
          case "3":
            e.preventDefault();
            handleNavigate("dns");
            break;
          case "4":
            e.preventDefault();
            handleNavigate("threats");
            break;
          case "5":
            e.preventDefault();
            handleNavigate("honeypot");
            break;
          case "6":
            e.preventDefault();
            handleNavigate("events");
            break;
          case "7":
            e.preventDefault();
            handleNavigate("reports");
            break;
          case "8":
          case ",":
            e.preventDefault();
            handleNavigate("settings");
            break;
        }
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [selectedEvent]);

  // Periodic Polling
  const refreshTelemetry = useCallback(async () => {
    try {
      const [mStatus, sStats, pkts, dQueries, evts, tTimeline, pMetrics, sDist, hLogs, hServices] =
        await Promise.all([
          api.getMonitoringStatus(),
          api.getSessionStats(),
          api.getLivePackets(250),
          api.getDnsQueries(200),
          api.getSecurityEvents(),
          api.getTrafficTimeline(),
          api.getProtocolDistribution(),
          api.getSeverityDistribution(),
          api.getHoneypotLogs(50),
          api.getHoneypotStatus(),
        ]);

      // Sound trigger for newly detected security events
      if (prevEventsCountRef.current !== null && evts.length > prevEventsCountRef.current) {
        const newEvents = evts.slice(prevEventsCountRef.current).filter((e) => e.status === "active");
        if (newEvents.length > 0) {
          const hasCritical = newEvents.some((e) => e.severity === "critical" || e.severity === "high");
          soundEffects.playThreatAlert(hasCritical ? "critical" : "medium");
        }
      }
      prevEventsCountRef.current = evts.length;

      // Sound trigger for new honeypot probes
      if (prevHoneypotCountRef.current !== null && hLogs.length > prevHoneypotCountRef.current) {
        soundEffects.playHoneypotTrigger();
      }
      prevHoneypotCountRef.current = hLogs.length;

      setMonitoringStatus(mStatus);
      setSessionStats(sStats);
      setLivePackets(pkts);
      setDnsQueries(dQueries);
      setEvents(evts);
      setTrafficTimeline(tTimeline);
      setProtocolMetrics(pMetrics);
      setSeverityDist(sDist);
      setHoneypotLogs(hLogs);
      setHoneypotServices(hServices);
    } catch (err) {
      console.error("Telemetry refresh error:", err);
    }
  }, []);

  useEffect(() => {
    const timer = setInterval(() => {
      refreshTelemetry();
    }, 1500);
    return () => clearInterval(timer);
  }, [refreshTelemetry]);

  // Actions
  const handleStartMonitoring = async () => {
    if (!selectedInterface) return;
    try {
      soundEffects.playMonitoringStart();
      const updated = await api.startMonitoring(
        selectedInterface,
        settings.preferred_backend as CaptureBackendType,
        !settings.privacy.payload_capture_enabled
      );
      setMonitoringStatus(updated);
      await refreshTelemetry();
    } catch (err) {
      alert("Failed to start monitoring: " + err);
    }
  };

  const handleStopMonitoring = async () => {
    try {
      soundEffects.playMonitoringStop();
      const updated = await api.stopMonitoring();
      setMonitoringStatus(updated);
      await refreshTelemetry();
    } catch (err) {
      alert("Failed to stop monitoring: " + err);
    }
  };

  const handleStartHoneypotService = async (serviceType: string, port: number, allowLan: boolean) => {
    try {
      const updated = await api.startHoneypotService(serviceType, port, allowLan);
      setHoneypotServices((prev) =>
        prev.map((s) => (s.service_type === updated.service_type ? updated : s))
      );
      await refreshTelemetry();
    } catch (err) {
      alert("Failed to start honeypot service: " + err);
    }
  };

  const handleStopHoneypotService = async (serviceType: string) => {
    try {
      const updated = await api.stopHoneypotService(serviceType);
      setHoneypotServices((prev) =>
        prev.map((s) => (s.service_type === updated.service_type ? updated : s))
      );
      await refreshTelemetry();
    } catch (err) {
      alert("Failed to stop honeypot service: " + err);
    }
  };

  const handleSimulateProbe = async (serviceType: string, probeTarget?: string) => {
    try {
      const res = await api.simulateHoneypotProbe(serviceType, probeTarget);
      soundEffects.playHoneypotTrigger();
      await refreshTelemetry();
      return res;
    } catch (err) {
      console.error("Simulation error:", err);
      throw err;
    }
  };

  const handleUpdateEventStatus = async (eventId: string, status: EventStatus, notes?: string) => {
    try {
      await api.updateEventStatus(eventId, status, notes);
      setEvents((prev) =>
        prev.map((e) =>
          e.event_id === eventId ? { ...e, status, user_notes: notes ?? e.user_notes } : e
        )
      );
      if (selectedEvent?.event_id === eventId) {
        setSelectedEvent((prev) =>
          prev ? { ...prev, status, user_notes: notes ?? prev.user_notes } : null
        );
      }
    } catch (err) {
      alert("Failed to update event status: " + err);
    }
  };

  const handleSaveSettings = async (newSettings: AppSettings) => {
    try {
      await api.saveAppSettings(newSettings);
      setSettings(newSettings);
    } catch (err) {
      alert("Failed to save settings: " + err);
    }
  };

  const handlePurgeDatabase = async (retentionDays?: number) => {
    try {
      await api.purgeDatabase(retentionDays);
      await refreshTelemetry();
      setSelectedEvent(null);
    } catch (err) {
      alert("Failed to purge records: " + err);
    }
  };

  const handleExportJson = async () => {
    try {
      const json = await api.exportEventsJson();
      const blob = new Blob([json], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `shadowsentry-events-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert("Export failed: " + err);
    }
  };

  const handleExportCsv = async () => {
    try {
      const csv = await api.exportEventsCsv();
      const blob = new Blob([csv], { type: "text/csv" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `shadowsentry-events-${Date.now()}.csv`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert("Export failed: " + err);
    }
  };

  const activeThreatsCount = events.filter((e) => e.status === "active").length;

  const handleStartupFading = React.useCallback(() => {
    setSplashFading(true);
  }, []);

  const handleStartupComplete = React.useCallback(() => {
    setShowStartup(false);
  }, []);

  return (
    <div style={{ display: "flex", width: "100vw", height: "100vh", overflow: "hidden", backgroundColor: "var(--color-bg)", position: "relative" }}>
      {showStartup && (
        <StartupDiagnosticScreen
          onComplete={handleStartupComplete}
          onFading={handleStartupFading}
          driverName={driverStatus.npcap_installed ? "Npcap L2 Promiscuous" : "Windows Raw Socket"}
          interfaceCount={interfaces.length}
        />
      )}

      {/* Main App Container with Cinematic Dissolve Entrance */}
      <div
        style={{
          display: "flex",
          flex: 1,
          width: "100%",
          height: "100%",
          minWidth: 0,
          transition: "opacity 0.85s cubic-bezier(0.16, 1, 0.3, 1), transform 0.85s cubic-bezier(0.16, 1, 0.3, 1), filter 0.85s cubic-bezier(0.16, 1, 0.3, 1)",
          opacity: showStartup && !splashFading ? 0.3 : 1,
          transform: showStartup && !splashFading ? "scale(0.985)" : "scale(1)",
          filter: showStartup && !splashFading ? "blur(5px)" : "blur(0px)",
          willChange: "opacity, transform, filter",
        }}
      >
        {/* Left Navigation Sidebar */}
        <AppSidebar
          activeTab={activeTab}
          onTabChange={handleNavigate}
          isMonitoring={monitoringStatus.is_active}
          activeThreatCount={activeThreatsCount}
          honeypotProbeCount={honeypotLogs.length}
          onOpenTutorial={() => setShowTutorial(true)}
        />

        {/* Main Desktop Viewport */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0, height: "100%" }}>
          {/* Top Status Bar */}
          <TopStatusBar
            isMonitoring={monitoringStatus.is_active}
            activeBackend={monitoringStatus.active_backend}
            selectedInterface={selectedInterface}
            interfaces={interfaces}
            onSelectInterface={setSelectedInterface}
            onStartMonitoring={handleStartMonitoring}
            onStopMonitoring={handleStopMonitoring}
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            onOpenSettings={() => handleNavigate("settings")}
            isCompact={isCompact}
            onToggleDensity={handleToggleDensity}
            isMuted={isMuted}
            onToggleMute={() => soundEffects.toggleMute()}
            currentTheme={currentTheme}
            onSelectTheme={handleSelectTheme}
            onOpenTutorial={() => setShowTutorial(true)}
          />

        {/* Content Body Area */}
        <main style={{ flex: 1, display: "flex", overflow: "hidden", position: "relative" }}>
          {activeTab === "dashboard" && (
            <DashboardPage
              monitoringStatus={monitoringStatus}
              sessionStats={sessionStats}
              protocolMetrics={protocolMetrics}
              timeline={trafficTimeline}
              severityDist={severityDist}
              recentEvents={events}
              driverStatus={driverStatus}
              gatewayInfo={gatewayInfo}
              onStartMonitoring={handleStartMonitoring}
              onStopMonitoring={handleStopMonitoring}
              onSelectEvent={setSelectedEvent}
              onRefresh={refreshTelemetry}
              onNavigateTab={setActiveTab}
              onOpenTutorial={() => setShowTutorial(true)}
            />
          )}

          {activeTab === "traffic" && (
            <LiveTrafficPage
              packets={livePackets}
              isMonitoring={monitoringStatus.is_active}
              onClearView={() => setLivePackets([])}
            />
          )}

          {activeTab === "dns" && (
            <DnsMonitorPage
              queries={dnsQueries}
              isMonitoring={monitoringStatus.is_active}
            />
          )}

          {activeTab === "threats" && (
            <ThreatCenterPage
              events={events}
              onSelectEvent={setSelectedEvent}
              selectedEventId={selectedEvent?.event_id}
              onUpdateStatus={handleUpdateEventStatus}
            />
          )}

          {activeTab === "honeypot" && (
            <HoneypotLabPage
              services={honeypotServices}
              logs={honeypotLogs}
              onStartService={handleStartHoneypotService}
              onStopService={handleStopHoneypotService}
              onSimulateProbe={handleSimulateProbe}
              onRefresh={refreshTelemetry}
            />
          )}

          {activeTab === "events" && (
            <EventHistoryPage
              events={events}
              onSelectEvent={setSelectedEvent}
              onExportJson={handleExportJson}
              onExportCsv={handleExportCsv}
              onPurgeDatabase={handlePurgeDatabase}
              onRefresh={refreshTelemetry}
            />
          )}

          {activeTab === "reports" && (
            <ReportsPage
              sessionStats={sessionStats}
              protocolMetrics={protocolMetrics}
              severityDist={severityDist}
              events={events}
              gatewayInfo={gatewayInfo}
              driverStatus={driverStatus}
              onExportJson={handleExportJson}
              onExportCsv={handleExportCsv}
            />
          )}

          {activeTab === "settings" && (
            <SettingsPage
              settings={settings}
              driverStatus={driverStatus}
              interfaces={interfaces}
              onSaveSettings={handleSaveSettings}
              onPurgeDatabase={handlePurgeDatabase}
              onRunLabScenario={api.runLabScenario}
            />
          )}

          {/* Explainable Event Details Slide-out Panel */}
          {selectedEvent && (
            <EventDetailsPanel
              event={selectedEvent}
              onClose={() => setSelectedEvent(null)}
              onUpdateStatus={handleUpdateEventStatus}
            />
          )}
        </main>

        {/* Bottom Status Bar */}
        <BottomStatusBar
          isMonitoring={monitoringStatus.is_active}
          durationSeconds={monitoringStatus.duration_seconds}
          interfaceName={monitoringStatus.selected_interface}
          packetCount={sessionStats.total_packets}
          isElevated={driverStatus.is_elevated_admin}
        />
      </div>
    </div>

    {/* Interactive Tutorial Guide Modal */}
    <TutorialGuideModal
      isOpen={showTutorial}
      onClose={() => setShowTutorial(false)}
      onNavigateTab={handleNavigate}
    />
  </div>
);
};
