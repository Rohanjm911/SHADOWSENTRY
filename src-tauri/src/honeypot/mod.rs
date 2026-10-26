// Local Honeypot Lab for SHADOWSENTRY
// Controlled, isolated opt-in security test laboratory.
// Loopback-only defaults. Strict bounds. No command execution. Never collects real credentials.

use crate::database::DatabaseManager;
use crate::detection::DetectionEngine;
use crate::models::{HoneypotInteractionLog, HoneypotServiceState, HoneypotServiceType};
use chrono::Utc;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use uuid::Uuid;

pub struct HoneypotLabManager {
    database: Arc<DatabaseManager>,
    detection: Arc<DetectionEngine>,
    services: Mutex<HashMap<HoneypotServiceType, HoneypotServiceState>>,
    shutdown_senders: Mutex<HashMap<HoneypotServiceType, broadcast::Sender<()>>>,
}

impl HoneypotLabManager {
    pub fn new(database: Arc<DatabaseManager>, detection: Arc<DetectionEngine>) -> Self {
        let mut services = HashMap::new();

        services.insert(
            HoneypotServiceType::HttpDecoy,
            HoneypotServiceState {
                service_type: HoneypotServiceType::HttpDecoy,
                name: "HTTP Decoy Server".to_string(),
                description: "Emulates web service with common reconnaissance targets (/admin, /.env, /api)".to_string(),
                is_running: false,
                bind_address: "127.0.0.1".to_string(),
                port: 8088,
                allow_lan: false,
                max_connections_per_minute: 60,
                total_connections_seen: 0,
                last_interaction_time: None,
                status_message: "Stopped. Loopback bind 127.0.0.1.".to_string(),
            },
        );

        services.insert(
            HoneypotServiceType::AdminPortal,
            HoneypotServiceState {
                service_type: HoneypotServiceType::AdminPortal,
                name: "Admin Portal Simulator".to_string(),
                description: "Emulates enterprise SSO administration gateway and logs reconnaissance scans safely".to_string(),
                is_running: false,
                bind_address: "127.0.0.1".to_string(),
                port: 8443,
                allow_lan: false,
                max_connections_per_minute: 40,
                total_connections_seen: 0,
                last_interaction_time: None,
                status_message: "Stopped. Loopback bind 127.0.0.1.".to_string(),
            },
        );

        services.insert(
            HoneypotServiceType::SshBanner,
            HoneypotServiceState {
                service_type: HoneypotServiceType::SshBanner,
                name: "SSH Banner Simulator".to_string(),
                description: "Emulates OpenSSH version banner and logs client scanner signatures without shell access".to_string(),
                is_running: false,
                bind_address: "127.0.0.1".to_string(),
                port: 2222,
                allow_lan: false,
                max_connections_per_minute: 30,
                total_connections_seen: 0,
                last_interaction_time: None,
                status_message: "Stopped. Loopback bind 127.0.0.1.".to_string(),
            },
        );

        Self {
            database,
            detection,
            services: Mutex::new(services),
            shutdown_senders: Mutex::new(HashMap::new()),
        }
    }

    pub fn get_status(&self) -> Vec<HoneypotServiceState> {
        self.services.lock().values().cloned().collect()
    }

    pub async fn start_service(
        self: &Arc<Self>,
        service_type: HoneypotServiceType,
        port: u16,
        allow_lan: bool,
    ) -> Result<HoneypotServiceState, String> {
        let bind_ip = if allow_lan { "0.0.0.0" } else { "127.0.0.1" };
        let bind_addr = format!("{}:{}", bind_ip, port);

        // Bind listener
        let listener = match TcpListener::bind(&bind_addr).await {
            Ok(l) => l,
            Err(e) => {
                let is_conflict = e.raw_os_error() == Some(10013) || e.raw_os_error() == Some(10048);
                if is_conflict {
                    return Err(format!(
                        "Port {} is already in use by another program on your PC (such as an active web server or service). Please change the Listening Port to an available port like 8088 or 8081 and try again.",
                        port
                    ));
                }
                return Err(format!(
                    "Failed to bind honeypot on {}: {}. Check if port is already in use or requires administrative elevation.",
                    bind_addr, e
                ));
            }
        };

        let (shutdown_tx, mut shutdown_rx) = broadcast::channel::<()>(1);
        self.shutdown_senders.lock().insert(service_type, shutdown_tx);

        {
            let mut svcs = self.services.lock();
            if let Some(s) = svcs.get_mut(&service_type) {
                s.is_running = true;
                s.bind_address = bind_ip.to_string();
                s.port = port;
                s.allow_lan = allow_lan;
                s.status_message = format!("Active and listening on {}:{}", bind_ip, port);
            }
        }

        let mgr = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((stream, client_addr)) => {
                                let mgr_inner = Arc::clone(&mgr);
                                tokio::spawn(async move {
                                    mgr_inner.handle_connection(service_type, stream, client_addr.ip().to_string(), client_addr.port()).await;
                                });
                            }
                            Err(_) => break,
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        break;
                    }
                }
            }
        });

        let updated = self.services.lock().get(&service_type).cloned().unwrap();
        Ok(updated)
    }

    pub fn stop_service(&self, service_type: HoneypotServiceType) -> HoneypotServiceState {
        if let Some(tx) = self.shutdown_senders.lock().remove(&service_type) {
            let _ = tx.send(());
        }

        let mut svcs = self.services.lock();
        if let Some(s) = svcs.get_mut(&service_type) {
            s.is_running = false;
            s.status_message = "Service stopped.".to_string();
            s.clone()
        } else {
            HoneypotServiceState {
                service_type,
                name: format!("{:?}", service_type),
                description: String::new(),
                is_running: false,
                bind_address: "127.0.0.1".to_string(),
                port: 0,
                allow_lan: false,
                max_connections_per_minute: 0,
                total_connections_seen: 0,
                last_interaction_time: None,
                status_message: "Stopped".to_string(),
            }
        }
    }

    pub fn stop_all(&self) {
        let mut senders = self.shutdown_senders.lock();
        for (_, tx) in senders.drain() {
            let _ = tx.send(());
        }
        let mut svcs = self.services.lock();
        for s in svcs.values_mut() {
            s.is_running = false;
            s.status_message = "Service stopped.".to_string();
        }
    }

    async fn handle_connection(
        &self,
        service_type: HoneypotServiceType,
        mut stream: tokio::net::TcpStream,
        client_ip: String,
        client_port: u16,
    ) {
        // Enforce 10-second bounded socket timeout
        let timeout_duration = std::time::Duration::from_secs(10);
        let now_str = Utc::now().to_rfc3339();

        {
            let mut svcs = self.services.lock();
            if let Some(s) = svcs.get_mut(&service_type) {
                s.total_connections_seen += 1;
                s.last_interaction_time = Some(now_str.clone());
            }
        }

        match service_type {
            HoneypotServiceType::HttpDecoy => {
                let mut buf = vec![0u8; 8192]; // Max 8KB request boundary
                if let Ok(Ok(n)) = tokio::time::timeout(timeout_duration, stream.read(&mut buf)).await {
                    if n > 0 {
                        let req_text = String::from_utf8_lossy(&buf[..n]);
                        let first_line = req_text.lines().next().unwrap_or("GET / HTTP/1.1");
                        let parts: Vec<&str> = first_line.split_whitespace().collect();
                        let method = parts.first().copied().unwrap_or("GET");
                        let path = parts.get(1).copied().unwrap_or("/");

                        let mut user_agent = None;
                        for line in req_text.lines() {
                            if line.to_lowercase().starts_with("user-agent:") {
                                user_agent = Some(line[11..].trim().to_string());
                                break;
                            }
                        }

                        let is_suspicious_probe = path.contains(".env")
                            || path.contains("admin")
                            || path.contains("wp-")
                            || path.contains("solr")
                            || path.contains("actuator")
                            || path.contains("api");

                        let log = HoneypotInteractionLog {
                            id: Uuid::new_v4().to_string(),
                            timestamp: now_str,
                            service_type,
                            client_ip: client_ip.clone(),
                            client_port,
                            request_method: Some(method.to_string()),
                            path: Some(path.to_string()),
                            probe_summary: format!("HTTP {} probe targeting '{}'", method, path),
                            user_agent,
                            payload_preview_sanitized: Some(first_line.to_string()),
                            flagged_as_suspicious: is_suspicious_probe,
                        };

                        let _ = self.database.insert_honeypot_log(&log);
                        if let Some(evt) = self.detection.evaluate_honeypot_interaction(&log) {
                            let _ = self.database.insert_event(&evt);
                        }

                        // Respond with realistic HTTP response
                        let response_body = if path == "/robots.txt" {
                            "User-agent: *\nDisallow: /admin\nDisallow: /.env\nDisallow: /api/v1/internal\n"
                        } else if path == "/.env" || path.contains("admin") {
                            "<html><head><title>Access Forbidden</title></head><body><h1>403 Forbidden</h1><p>Administrative authentication required.</p></body></html>"
                        } else {
                            "<!DOCTYPE html><html><head><title>Internal Portal</title></head><body><h2>Workstation Service Gateway</h2><p>Operational status: Active</p></body></html>"
                        };

                        let http_resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nServer: Microsoft-IIS/10.0\r\n\r\n{}",
                            response_body.len(),
                            response_body
                        );
                        let _ = stream.write_all(http_resp.as_bytes()).await;
                    }
                }
            }
            HoneypotServiceType::AdminPortal => {
                let mut buf = vec![0u8; 8192];
                if let Ok(Ok(n)) = tokio::time::timeout(timeout_duration, stream.read(&mut buf)).await {
                    if n > 0 {
                        let req_text = String::from_utf8_lossy(&buf[..n]);
                        let first_line = req_text.lines().next().unwrap_or("GET / HTTP/1.1");
                        let parts: Vec<&str> = first_line.split_whitespace().collect();
                        let method = parts.first().copied().unwrap_or("GET");
                        let path = parts.get(1).copied().unwrap_or("/");

                        let is_post_login = method == "POST" || path.contains("login") || path.contains("auth");

                        let log = HoneypotInteractionLog {
                            id: Uuid::new_v4().to_string(),
                            timestamp: now_str,
                            service_type,
                            client_ip: client_ip.clone(),
                            client_port,
                            request_method: Some(method.to_string()),
                            path: Some(path.to_string()),
                            probe_summary: if is_post_login {
                                "Credential attempt submitted against Admin Portal decoy (Safely rejected, no credentials captured)".to_string()
                            } else {
                                format!("Admin portal reconnaissance: {} {}", method, path)
                            },
                            user_agent: None,
                            payload_preview_sanitized: Some(format!("Request: {} {}", method, path)),
                            flagged_as_suspicious: true,
                        };

                        let _ = self.database.insert_honeypot_log(&log);
                        if let Some(evt) = self.detection.evaluate_honeypot_interaction(&log) {
                            let _ = self.database.insert_event(&evt);
                        }

                        let html = r#"<!DOCTYPE html>
<html>
<head><title>Enterprise Single Sign-On</title></head>
<body style="font-family:Segoe UI, sans-serif; background:#10161E; color:#F3F6FA; display:flex; align-items:center; justify-content:center; height:100vh;">
  <div style="background:#151D27; padding:32px; border:1px solid #293342; border-radius:6px; width:340px;">
    <h3>Administrative Gateway</h3>
    <p style="color:#A8B3C2; font-size:12px;">Authentication Required</p>
    <div style="color:#FF5D68; font-size:12px; margin-top:12px;">Access Denied. Multi-factor hardware key not present.</div>
  </div>
</body>
</html>"#;
                        let resp = format!(
                            "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            html.len(),
                            html
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                    }
                }
            }
            HoneypotServiceType::SshBanner => {
                // Send standard OpenSSH banner
                let banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n";
                let _ = stream.write_all(banner).await;

                // Read client banner (e.g. scanner software identity)
                let mut client_banner = vec![0u8; 512];
                if let Ok(Ok(n)) = tokio::time::timeout(timeout_duration, stream.read(&mut client_banner)).await {
                    let client_str = if n > 0 {
                        String::from_utf8_lossy(&client_banner[..n]).trim().to_string()
                    } else {
                        "No identification string received".to_string()
                    };

                    let log = HoneypotInteractionLog {
                        id: Uuid::new_v4().to_string(),
                        timestamp: now_str,
                        service_type,
                        client_ip: client_ip.clone(),
                        client_port,
                        request_method: Some("SSH-HANDSHAKE".to_string()),
                        path: None,
                        probe_summary: format!("SSH scanner connection. Client banner: '{}'", client_str),
                        user_agent: None,
                        payload_preview_sanitized: Some(client_str),
                        flagged_as_suspicious: true,
                    };

                    let _ = self.database.insert_honeypot_log(&log);
                    if let Some(evt) = self.detection.evaluate_honeypot_interaction(&log) {
                        let _ = self.database.insert_event(&evt);
                    }
                }
                // Close socket immediately without authentication
                let _ = stream.shutdown().await;
            }
        }
    }
}
