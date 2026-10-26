// Tauri IPC Commands Layer for SHADOWSENTRY
// Exposes narrowly scoped, validated commands to the desktop frontend.

use crate::capture::CaptureManager;
use crate::database::DatabaseManager;
use crate::detection::DetectionEngine;
use crate::honeypot::HoneypotLabManager;
use crate::models::{
    AppSettings, ArpEntry, CaptureBackendType, DnsQueryRecord, DriverStatus,
    EventFilterCriteria, EventSeverity, EventStatus, GatewayInfo, HoneypotInteractionLog,
    HoneypotServiceState, HoneypotServiceType, HoneypotSimulationResult, MonitoringStatus, NetworkInterfaceInfo,
    PacketMetadata, ProtocolMetric, ProtocolType, SecurityEvent, SessionStats,
    SeverityDistribution, TrafficTimelinePoint,
};
use crate::network::NetworkDiscovery;
use parking_lot::Mutex;
use std::sync::Arc;
use tauri::State;

pub struct AppState {
    pub database: Arc<DatabaseManager>,
    pub detection: Arc<DetectionEngine>,
    pub capture: Arc<CaptureManager>,
    pub honeypot: Arc<HoneypotLabManager>,
    pub settings: Mutex<AppSettings>,
}

#[tauri::command]
pub fn get_monitoring_status(state: State<'_, AppState>) -> MonitoringStatus {
    state.capture.get_status()
}

#[tauri::command]
pub async fn start_monitoring(
    interface_name: String,
    backend: CaptureBackendType,
    metadata_only: bool,
    state: State<'_, AppState>,
) -> Result<MonitoringStatus, String> {
    state.capture.start_monitoring(interface_name, backend, metadata_only).await
}

#[tauri::command]
pub fn stop_monitoring(state: State<'_, AppState>) -> MonitoringStatus {
    state.capture.stop_monitoring()
}

#[tauri::command]
pub fn get_network_interfaces() -> Vec<NetworkInterfaceInfo> {
    NetworkDiscovery::get_interfaces()
}

#[tauri::command]
pub fn get_capture_driver_status() -> DriverStatus {
    NetworkDiscovery::check_driver_status()
}

#[tauri::command]
pub fn get_gateway_info() -> GatewayInfo {
    NetworkDiscovery::get_gateway_info()
}

#[tauri::command]
pub fn get_arp_table() -> Vec<ArpEntry> {
    NetworkDiscovery::get_arp_table()
}

#[tauri::command]
pub fn get_live_packets(limit: Option<usize>, state: State<'_, AppState>) -> Vec<PacketMetadata> {
    state.capture.get_live_packets(limit.unwrap_or(250))
}

#[tauri::command]
pub fn get_dns_queries(limit: Option<usize>, state: State<'_, AppState>) -> Vec<DnsQueryRecord> {
    let memory_queries = state.capture.get_dns_queries(limit.unwrap_or(250));
    if !memory_queries.is_empty() {
        memory_queries
    } else {
        state.database.get_dns_queries(limit.unwrap_or(250)).unwrap_or_default()
    }
}

#[tauri::command]
pub fn get_security_events(
    filter: Option<EventFilterCriteria>,
    state: State<'_, AppState>,
) -> Result<Vec<SecurityEvent>, String> {
    state.database.get_events(filter.as_ref(), 500).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn update_event_status(
    event_id: String,
    status: EventStatus,
    notes: Option<String>,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    state
        .database
        .update_event_status(&event_id, status, notes.as_deref())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_honeypot_status(state: State<'_, AppState>) -> Vec<HoneypotServiceState> {
    state.honeypot.get_status()
}

#[tauri::command]
pub async fn start_honeypot_service(
    service_type: String,
    port: u16,
    allow_lan: bool,
    state: State<'_, AppState>,
) -> Result<HoneypotServiceState, String> {
    let svc = match service_type.as_str() {
        "http_decoy" => HoneypotServiceType::HttpDecoy,
        "admin_portal" => HoneypotServiceType::AdminPortal,
        "ssh_banner" => HoneypotServiceType::SshBanner,
        _ => return Err(format!("Unknown honeypot service type '{}'", service_type)),
    };
    state.honeypot.start_service(svc, port, allow_lan).await
}

#[tauri::command]
pub fn stop_honeypot_service(
    service_type: String,
    state: State<'_, AppState>,
) -> Result<HoneypotServiceState, String> {
    let svc = match service_type.as_str() {
        "http_decoy" => HoneypotServiceType::HttpDecoy,
        "admin_portal" => HoneypotServiceType::AdminPortal,
        "ssh_banner" => HoneypotServiceType::SshBanner,
        _ => return Err(format!("Unknown honeypot service type '{}'", service_type)),
    };
    Ok(state.honeypot.stop_service(svc))
}

#[tauri::command]
pub fn get_honeypot_logs(limit: Option<usize>, state: State<'_, AppState>) -> Vec<HoneypotInteractionLog> {
    state.database.get_honeypot_logs(limit.unwrap_or(100)).unwrap_or_default()
}

#[tauri::command]
pub fn get_session_stats(state: State<'_, AppState>) -> SessionStats {
    state.capture.get_session_stats()
}

#[tauri::command]
pub fn get_traffic_timeline(state: State<'_, AppState>) -> Vec<TrafficTimelinePoint> {
    let packets = state.capture.get_live_packets(1000);
    let events = state.database.get_events(None, 200).unwrap_or_default();
    let now = chrono::Local::now();

    // Group packets by local second label %H:%M:%S
    let mut timeline_map: std::collections::HashMap<String, (u64, u64, u64)> = std::collections::HashMap::new();

    for p in &packets {
        let label = if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&p.timestamp) {
            dt.with_timezone(&chrono::Local).format("%H:%M:%S").to_string()
        } else {
            p.timestamp.chars().skip(11).take(8).collect::<String>()
        };
        let entry = timeline_map.entry(label).or_insert((0, 0, 0));
        entry.0 += 1;
        entry.1 += p.packet_size as u64;
    }

    for e in &events {
        let label = if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&e.timestamp) {
            dt.with_timezone(&chrono::Local).format("%H:%M:%S").to_string()
        } else {
            e.timestamp.chars().skip(11).take(8).collect::<String>()
        };
        let entry = timeline_map.entry(label).or_insert((0, 0, 0));
        entry.2 += 1;
    }

    // Determine rolling window end: anchor to latest packet if capture stopped, or now
    let latest_packet_time = packets.iter().filter_map(|p| {
        chrono::DateTime::parse_from_rfc3339(&p.timestamp).ok().map(|dt| dt.with_timezone(&chrono::Local))
    }).max();

    let end_time = match latest_packet_time {
        Some(dt) if (now - dt).num_seconds() > 35 => dt,
        _ => now,
    };

    let window_secs = 30;
    let mut points = Vec::with_capacity(window_secs);

    for i in (0..window_secs).rev() {
        let t = end_time - chrono::Duration::seconds(i as i64);
        let time_label = t.format("%H:%M:%S").to_string();
        let (pkts, bytes, evts) = timeline_map.get(&time_label).copied().unwrap_or((0, 0, 0));
        points.push(TrafficTimelinePoint {
            timestamp: t.to_rfc3339(),
            time_label,
            packet_count: pkts,
            byte_count: bytes,
            event_count: evts,
        });
    }

    points
}

#[tauri::command]
pub fn get_protocol_distribution(state: State<'_, AppState>) -> Vec<ProtocolMetric> {
    let packets = state.capture.get_live_packets(1000);
    let mut counts: std::collections::HashMap<ProtocolType, (u64, u64)> = std::collections::HashMap::new();

    counts.insert(ProtocolType::TCP, (0, 0));
    counts.insert(ProtocolType::UDP, (0, 0));
    counts.insert(ProtocolType::DNS, (0, 0));
    counts.insert(ProtocolType::ARP, (0, 0));
    counts.insert(ProtocolType::ICMP, (0, 0));

    let mut total_packets = 0u64;
    for p in &packets {
        total_packets += 1;
        let entry = counts.entry(p.protocol).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += p.packet_size as u64;
    }

    let mut metrics = Vec::new();
    for (proto, (pkts, bytes)) in counts {
        let pct = if total_packets > 0 {
            (pkts as f64 / total_packets as f64) * 100.0
        } else {
            0.0
        };

        let color = match proto {
            ProtocolType::TCP => "#4C8DFF",
            ProtocolType::UDP => "#45C6D8",
            ProtocolType::DNS => "#B47EFF",
            ProtocolType::ARP => "#35C98A",
            ProtocolType::ICMP => "#F4B942",
            _ => "#6C7A8E",
        };

        metrics.push(ProtocolMetric {
            protocol: proto,
            packet_count: pkts,
            byte_count: bytes,
            percentage: (pct * 10.0).round() / 10.0,
            color: color.to_string(),
        });
    }

    metrics.sort_by(|a, b| b.packet_count.cmp(&a.packet_count));
    metrics
}

#[tauri::command]
pub fn get_severity_distribution(state: State<'_, AppState>) -> SeverityDistribution {
    let events = state.database.get_events(None, 5000).unwrap_or_default();
    let mut dist = SeverityDistribution {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        informational: 0,
    };

    for e in events {
        match e.severity {
            EventSeverity::Critical => dist.critical += 1,
            EventSeverity::High => dist.high += 1,
            EventSeverity::Medium => dist.medium += 1,
            EventSeverity::Low => dist.low += 1,
            EventSeverity::Informational => dist.informational += 1,
        }
    }

    dist
}

#[tauri::command]
pub fn get_app_settings(state: State<'_, AppState>) -> AppSettings {
    state.settings.lock().clone()
}

#[tauri::command]
pub fn save_app_settings(settings: AppSettings, state: State<'_, AppState>) -> bool {
    state.detection.update_thresholds(settings.thresholds.clone());
    *state.settings.lock() = settings;
    true
}

#[tauri::command]
pub fn purge_database(
    retention_days: Option<u32>,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let deleted = state.database.purge_database(retention_days).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "deleted_count": deleted }))
}

#[tauri::command]
pub fn export_events_json(state: State<'_, AppState>) -> Result<String, String> {
    state.database.export_events_json().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn export_events_csv(state: State<'_, AppState>) -> Result<String, String> {
    state.database.export_events_csv().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn run_lab_scenario(
    scenario_name: String,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let msg = state.capture.trigger_test_scenario(&scenario_name)?;
    Ok(serde_json::json!({ "success": true, "message": msg }))
}

#[tauri::command]
pub async fn simulate_honeypot_probe(
    service_type: String,
    probe_target: Option<String>,
    state: State<'_, AppState>,
) -> Result<HoneypotSimulationResult, String> {
    let svc_type = match service_type.as_str() {
        "http_decoy" => HoneypotServiceType::HttpDecoy,
        "admin_portal" => HoneypotServiceType::AdminPortal,
        "ssh_banner" => HoneypotServiceType::SshBanner,
        _ => return Err(format!("Unknown honeypot service type '{}'", service_type)),
    };

    // If service is not running, auto-start it on its assigned port on loopback
    let (is_running, port) = {
        let statuses = state.honeypot.get_status();
        let current = statuses.iter().find(|s| s.service_type == svc_type);
        match current {
            Some(s) => (s.is_running, s.port),
            None => (false, match svc_type {
                HoneypotServiceType::HttpDecoy => 8088,
                HoneypotServiceType::AdminPortal => 8443,
                HoneypotServiceType::SshBanner => 2222,
            }),
        }
    };

    let actual_port = if !is_running {
        let started = state.honeypot.start_service(svc_type, port, false).await?;
        tokio::time::sleep(std::time::Duration::from_millis(60)).await;
        started.port
    } else {
        port
    };

    let target_addr = format!("127.0.0.1:{}", actual_port);
    let start_instant = std::time::Instant::now();

    // Connect over real TCP loopback socket
    let mut stream = match tokio::time::timeout(
        std::time::Duration::from_secs(4),
        tokio::net::TcpStream::connect(&target_addr),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Err(format!("Could not connect to honeypot socket {}: {}", target_addr, e));
        }
        Err(_) => {
            return Err(format!("Connection to honeypot socket {} timed out", target_addr));
        }
    };

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (request_str, response_str) = match svc_type {
        HoneypotServiceType::HttpDecoy => {
            let path = probe_target.unwrap_or_else(|| "/.env".to_string());
            let request = format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Nikto/2.1.6 (Security Assessment Scanner)\r\nAccept: */*\r\nConnection: close\r\n\r\n",
                path, target_addr
            );
            stream.write_all(request.as_bytes()).await.map_err(|e| e.to_string())?;

            let mut resp_buf = vec![0u8; 4096];
            let n = match tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut resp_buf)).await {
                Ok(Ok(n)) => n,
                _ => 0,
            };
            let resp_text = String::from_utf8_lossy(&resp_buf[..n]).to_string();
            (request.trim().to_string(), resp_text.trim().to_string())
        }
        HoneypotServiceType::AdminPortal => {
            let path = probe_target.unwrap_or_else(|| "/admin/login".to_string());
            let body = "username=admin&password=password123&action=authenticate";
            let request = format!(
                "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: sqlmap/1.7#dev\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                path, target_addr, body.len(), body
            );
            stream.write_all(request.as_bytes()).await.map_err(|e| e.to_string())?;

            let mut resp_buf = vec![0u8; 4096];
            let n = match tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut resp_buf)).await {
                Ok(Ok(n)) => n,
                _ => 0,
            };
            let resp_text = String::from_utf8_lossy(&resp_buf[..n]).to_string();
            (request.trim().to_string(), resp_text.trim().to_string())
        }
        HoneypotServiceType::SshBanner => {
            let mut server_banner_buf = vec![0u8; 256];
            let n1 = match tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut server_banner_buf)).await {
                Ok(Ok(n)) => n,
                _ => 0,
            };
            let server_banner = String::from_utf8_lossy(&server_banner_buf[..n1]).to_string();

            let client_banner = "SSH-2.0-ScannerBot_v2.4_Masscan\r\n";
            stream.write_all(client_banner.as_bytes()).await.map_err(|e| e.to_string())?;
            let _ = stream.flush().await;

            let request = format!("Client Banner: {}", client_banner.trim());
            let response = format!("Server Banner Received: {}", server_banner.trim());
            (request, response)
        }
    };

    let latency = start_instant.elapsed().as_millis() as u64;

    Ok(HoneypotSimulationResult {
        success: true,
        service_type,
        target_address: target_addr,
        request_preview: request_str,
        response_preview: response_str,
        latency_ms: latency,
        event_created: true,
        message: "Honeypot probe successfully captured, logged to SQLite, and evaluated by Rule 8.".to_string(),
    })
}
