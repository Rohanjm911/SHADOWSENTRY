import { invoke } from "@tauri-apps/api/core";
import {
  NetworkInterfaceInfo,
  DriverStatus,
  MonitoringStatus,
  GatewayInfo,
  ArpEntry,
  CaptureBackendType,
} from "../types/network";
import { PacketMetadata, DnsQueryRecord } from "../types/packet";
import { SecurityEvent, EventStatus, EventFilterCriteria } from "../types/event";
import { HoneypotServiceState, HoneypotInteractionLog, HoneypotSimulationResult } from "../types/honeypot";
import { SessionStats, TrafficTimelinePoint, ProtocolMetric, SeverityDistribution } from "../types/stats";
import { AppSettings } from "../types/settings";

// Helper to detect if running in real Tauri native desktop environment
export function isTauriEnvironment(): boolean {
  return typeof window !== "undefined" && Boolean((window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__);
}

export async function getNetworkInterfaces(): Promise<NetworkInterfaceInfo[]> {
  if (isTauriEnvironment()) {
    return await invoke<NetworkInterfaceInfo[]>("get_network_interfaces");
  }
  return getMockInterfaces();
}

export async function getCaptureDriverStatus(): Promise<DriverStatus> {
  if (isTauriEnvironment()) {
    return await invoke<DriverStatus>("get_capture_driver_status");
  }
  return {
    npcap_installed: false,
    npcap_version: null,
    npcap_service_running: false,
    is_elevated_admin: true,
    raw_sockets_supported: true,
    supported_backends: ["raw_socket", "iphelper", "lab_synthetic"],
    recommended_backend: "raw_socket",
    diagnostic_notes: [
      "Npcap driver not detected on system path.",
      "Windows Raw Sockets (Administrator) backend is available for IP-layer monitoring.",
      "Windows IP Helper APIs available for gateway and ARP monitoring.",
      "Laboratory simulation mode available for security rule verification.",
    ],
  };
}

export async function getGatewayInfo(): Promise<GatewayInfo> {
  if (isTauriEnvironment()) {
    return await invoke<GatewayInfo>("get_gateway_info");
  }
  return {
    ip_address: "192.168.1.1",
    mac_address: "70:4f:57:a2:bb:01",
    interface_name: "Ethernet 1",
    interface_index: 12,
    metric: 25,
    is_reachable: true,
    last_observed: new Date().toISOString(),
    consecutive_changes: 0,
  };
}

export async function getArpTable(): Promise<ArpEntry[]> {
  if (isTauriEnvironment()) {
    return await invoke<ArpEntry[]>("get_arp_table");
  }
  return [
    {
      ip_address: "192.168.1.1",
      mac_address: "70:4f:57:a2:bb:01",
      interface_index: 12,
      entry_type: "dynamic",
      state: "Reachable",
      last_updated: new Date().toISOString(),
      is_anomaly: false,
    },
    {
      ip_address: "192.168.1.105",
      mac_address: "00:e0:4c:68:01:23",
      interface_index: 12,
      entry_type: "dynamic",
      state: "Reachable",
      last_updated: new Date().toISOString(),
      is_anomaly: false,
    },
    {
      ip_address: "192.168.1.254",
      mac_address: "70:4f:57:a2:bb:01",
      interface_index: 12,
      entry_type: "dynamic",
      state: "Reachable",
      last_updated: new Date().toISOString(),
      is_anomaly: true, // Example MAC collision anomaly for inspection
    },
  ];
}

export async function getMonitoringStatus(): Promise<MonitoringStatus> {
  if (isTauriEnvironment()) {
    return await invoke<MonitoringStatus>("get_monitoring_status");
  }
  return {
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
  };
}

export async function startMonitoring(
  interfaceName: string,
  backend: CaptureBackendType,
  metadataOnly: boolean
): Promise<MonitoringStatus> {
  if (isTauriEnvironment()) {
    return await invoke<MonitoringStatus>("start_monitoring", {
      interfaceName,
      backend,
      metadataOnly,
    });
  }
  return {
    is_active: true,
    active_backend: backend,
    selected_interface: interfaceName,
    session_id: "sess-" + Date.now(),
    start_time: new Date().toISOString(),
    duration_seconds: 1,
    packet_count: 142,
    byte_count: 94820,
    event_count: 0,
    is_paused: false,
    metadata_only_mode: metadataOnly,
    error_message: null,
  };
}

export async function stopMonitoring(): Promise<MonitoringStatus> {
  if (isTauriEnvironment()) {
    return await invoke<MonitoringStatus>("stop_monitoring");
  }
  return {
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
  };
}

export async function getLivePackets(limit: number = 250): Promise<PacketMetadata[]> {
  if (isTauriEnvironment()) {
    return await invoke<PacketMetadata[]>("get_live_packets", { limit });
  }
  return [];
}

export async function getDnsQueries(limit: number = 250): Promise<DnsQueryRecord[]> {
  if (isTauriEnvironment()) {
    return await invoke<DnsQueryRecord[]>("get_dns_queries", { limit });
  }
  return [];
}

export async function getSecurityEvents(filter?: EventFilterCriteria): Promise<SecurityEvent[]> {
  if (isTauriEnvironment()) {
    return await invoke<SecurityEvent[]>("get_security_events", { filter });
  }
  return [];
}

export async function updateEventStatus(
  eventId: string,
  status: EventStatus,
  notes?: string
): Promise<boolean> {
  if (isTauriEnvironment()) {
    return await invoke<boolean>("update_event_status", { eventId, status, notes });
  }
  return true;
}

export async function getHoneypotStatus(): Promise<HoneypotServiceState[]> {
  if (isTauriEnvironment()) {
    return await invoke<HoneypotServiceState[]>("get_honeypot_status");
  }
  return [
    {
      service_type: "http_decoy",
      name: "HTTP Decoy Server",
      description: "Emulates high-interaction web service with decoy endpoints (/admin, /.env, /api)",
      is_running: false,
      bind_address: "127.0.0.1",
      port: 8088,
      allow_lan: false,
      max_connections_per_minute: 60,
      total_connections_seen: 0,
      last_interaction_time: null,
      status_message: "Stopped. Binds to loopback interface only.",
    },
    {
      service_type: "admin_portal",
      name: "Admin Portal Decoy",
      description: "Realistic corporate single-sign-on decoy capturing reconnaissance attempts safely",
      is_running: false,
      bind_address: "127.0.0.1",
      port: 8443,
      allow_lan: false,
      max_connections_per_minute: 40,
      total_connections_seen: 0,
      last_interaction_time: null,
      status_message: "Stopped. No credentials stored.",
    },
    {
      service_type: "ssh_banner",
      name: "SSH Banner Simulator",
      description: "Emulates standard OpenSSH banner and logs client handshake identifiers",
      is_running: false,
      bind_address: "127.0.0.1",
      port: 2222,
      allow_lan: false,
      max_connections_per_minute: 30,
      total_connections_seen: 0,
      last_interaction_time: null,
      status_message: "Stopped. Loopback-only service.",
    },
  ];
}

export async function startHoneypotService(
  serviceType: string,
  port: number,
  allowLan: boolean
): Promise<HoneypotServiceState> {
  if (isTauriEnvironment()) {
    return await invoke<HoneypotServiceState>("start_honeypot_service", {
      serviceType,
      port,
      allowLan,
    });
  }
  return {
    service_type: serviceType as unknown as HoneypotServiceState["service_type"],
    name: serviceType,
    description: "Running in lab preview mode",
    is_running: true,
    bind_address: allowLan ? "0.0.0.0" : "127.0.0.1",
    port,
    allow_lan: allowLan,
    max_connections_per_minute: 60,
    total_connections_seen: 1,
    last_interaction_time: new Date().toISOString(),
    status_message: `Listening on ${allowLan ? "0.0.0.0" : "127.0.0.1"}:${port}`,
  };
}

export async function stopHoneypotService(serviceType: string): Promise<HoneypotServiceState> {
  if (isTauriEnvironment()) {
    return await invoke<HoneypotServiceState>("stop_honeypot_service", { serviceType });
  }
  return {
    service_type: serviceType as unknown as HoneypotServiceState["service_type"],
    name: serviceType,
    description: "Stopped",
    is_running: false,
    bind_address: "127.0.0.1",
    port: 8088,
    allow_lan: false,
    max_connections_per_minute: 60,
    total_connections_seen: 0,
    last_interaction_time: null,
    status_message: "Service stopped.",
  };
}

export async function getHoneypotLogs(limit: number = 100): Promise<HoneypotInteractionLog[]> {
  if (isTauriEnvironment()) {
    return await invoke<HoneypotInteractionLog[]>("get_honeypot_logs", { limit });
  }
  return [];
}

export async function simulateHoneypotProbe(
  serviceType: string,
  probeTarget?: string
): Promise<HoneypotSimulationResult> {
  if (isTauriEnvironment()) {
    return await invoke<HoneypotSimulationResult>("simulate_honeypot_probe", {
      serviceType,
      probeTarget,
    });
  }
  return {
    success: true,
    service_type: serviceType,
    target_address: `127.0.0.1:${serviceType === "http_decoy" ? 8088 : serviceType === "admin_portal" ? 8443 : 2222}`,
    request_preview: `GET ${probeTarget || "/.env"} HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Nikto/2.1.6`,
    response_preview: `HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nContent-Type: text/html\r\n\r\n403 Forbidden - Authentication Required`,
    latency_ms: 2,
    event_created: true,
    message: "Honeypot probe captured and logged to SQLite.",
  };
}

export async function getSessionStats(): Promise<SessionStats> {
  if (isTauriEnvironment()) {
    return await invoke<SessionStats>("get_session_stats");
  }
  return {
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
  };
}

export async function getTrafficTimeline(): Promise<TrafficTimelinePoint[]> {
  if (isTauriEnvironment()) {
    return await invoke<TrafficTimelinePoint[]>("get_traffic_timeline");
  }
  return [];
}

export async function getProtocolDistribution(): Promise<ProtocolMetric[]> {
  if (isTauriEnvironment()) {
    return await invoke<ProtocolMetric[]>("get_protocol_distribution");
  }
  return [
    { protocol: "TCP", packet_count: 0, byte_count: 0, percentage: 0, color: "#4C8DFF" },
    { protocol: "UDP", packet_count: 0, byte_count: 0, percentage: 0, color: "#45C6D8" },
    { protocol: "DNS", packet_count: 0, byte_count: 0, percentage: 0, color: "#B47EFF" },
    { protocol: "ARP", packet_count: 0, byte_count: 0, percentage: 0, color: "#35C98A" },
    { protocol: "ICMP", packet_count: 0, byte_count: 0, percentage: 0, color: "#F4B942" },
  ];
}

export async function getSeverityDistribution(): Promise<SeverityDistribution> {
  if (isTauriEnvironment()) {
    return await invoke<SeverityDistribution>("get_severity_distribution");
  }
  return { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
}

export async function getAppSettings(): Promise<AppSettings> {
  if (isTauriEnvironment()) {
    return await invoke<AppSettings>("get_app_settings");
  }
  return {
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
  };
}

export async function saveAppSettings(settings: AppSettings): Promise<boolean> {
  if (isTauriEnvironment()) {
    return await invoke<boolean>("save_app_settings", { settings });
  }
  return true;
}

export async function purgeDatabase(retentionDays?: number): Promise<{ deleted_count: number }> {
  if (isTauriEnvironment()) {
    return await invoke<{ deleted_count: number }>("purge_database", { retentionDays });
  }
  return { deleted_count: 0 };
}

export async function exportEventsJson(): Promise<string> {
  if (isTauriEnvironment()) {
    return await invoke<string>("export_events_json");
  }
  return "[]";
}

export async function exportEventsCsv(): Promise<string> {
  if (isTauriEnvironment()) {
    return await invoke<string>("export_events_csv");
  }
  return "timestamp,rule_name,severity,category,source_ip,dest_ip,status\n";
}

export async function runLabScenario(scenarioName: string): Promise<{ success: boolean; message: string }> {
  if (isTauriEnvironment()) {
    return await invoke<{ success: boolean; message: string }>("run_lab_scenario", { scenarioName });
  }
  return { success: true, message: `Simulated scenario '${scenarioName}' executed in preview mode.` };
}

function getMockInterfaces(): NetworkInterfaceInfo[] {
  return [
    {
      id: "{E79A12B0-8354-46CD-B55E-FA1B08C757B3}",
      name: "Ethernet 1",
      friendly_name: "Intel(R) Ethernet Controller I225-V",
      description: "Intel Gigabit Adapter",
      mac_address: "A8:5E:45:9B:10:C2",
      ipv4_addresses: ["192.168.1.145"],
      ipv6_addresses: ["fe80::10bc:4432:9812:d3fa"],
      gateway_ips: ["192.168.1.1"],
      is_up: true,
      is_loopback: false,
      is_wireless: false,
      speed_mbps: 1000,
      mtu: 1500,
    },
    {
      id: "{A12B34C5-9988-7766-5544-33221100AABB}",
      name: "Wi-Fi",
      friendly_name: "Intel(R) Wi-Fi 6 AX200 160MHz",
      description: "Wireless 802.11ax Adapter",
      mac_address: "B4:96:91:22:8A:4D",
      ipv4_addresses: ["192.168.50.88"],
      ipv6_addresses: [],
      gateway_ips: ["192.168.50.1"],
      is_up: true,
      is_loopback: false,
      is_wireless: true,
      speed_mbps: 866,
      mtu: 1500,
    },
    {
      id: "{00000000-0000-0000-0000-000000000001}",
      name: "Loopback",
      friendly_name: "Software Loopback Interface 1",
      description: "Local Loopback",
      mac_address: "00:00:00:00:00:00",
      ipv4_addresses: ["127.0.0.1"],
      ipv6_addresses: ["::1"],
      gateway_ips: [],
      is_up: true,
      is_loopback: true,
      is_wireless: false,
      speed_mbps: 10000,
      mtu: 65536,
    },
  ];
}
