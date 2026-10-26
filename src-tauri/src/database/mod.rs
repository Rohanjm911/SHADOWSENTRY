// Local-first SQLite Database layer for SHADOWSENTRY
// Privacy-first: no mandatory cloud account, no telemetry, bounded storage.

use crate::models::{
    DnsQueryRecord, EventFilterCriteria, EventSeverity, EventStatus, HoneypotInteractionLog,
    SecurityEvent, SessionStats,
};
use chrono::Utc;
use parking_lot::Mutex;
use rusqlite::{params, Connection, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct DatabaseManager {
    conn: Arc<Mutex<Connection>>,
    db_path: PathBuf,
}

impl DatabaseManager {
    /// Initialize local database in %LOCALAPPDATA%\ShadowSentry or current working directory
    pub fn new() -> Result<Self> {
        let app_data_dir = if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
            let p = Path::new(&local_appdata).join("ShadowSentry");
            std::fs::create_dir_all(&p).ok();
            p
        } else {
            PathBuf::from(".")
        };

        let db_path = app_data_dir.join("shadowsentry.db");
        let conn = Connection::open(&db_path)?;

        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
            db_path,
        };

        db.initialize_schema()?;
        Ok(db)
    }

    /// Create in-memory database for testing
    pub fn new_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
            db_path: PathBuf::from(":memory:"),
        };
        db.initialize_schema()?;
        Ok(db)
    }

    pub fn get_path(&self) -> String {
        self.db_path.to_string_lossy().to_string()
    }

    fn initialize_schema(&self) -> Result<()> {
        let conn = self.conn.lock();

        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;

            CREATE TABLE IF NOT EXISTS security_events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT,
                source_port INTEGER,
                dest_ip TEXT,
                dest_port INTEGER,
                protocol TEXT,
                interface_name TEXT,
                what_observed TEXT NOT NULL,
                why_flagged TEXT NOT NULL,
                supporting_evidence TEXT NOT NULL,
                uncertainty_details TEXT NOT NULL,
                confidence_score REAL NOT NULL,
                recommended_steps TEXT NOT NULL,
                status TEXT NOT NULL,
                user_notes TEXT,
                resolved_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity);
            CREATE INDEX IF NOT EXISTS idx_events_status ON security_events(status);

            CREATE TABLE IF NOT EXISTS monitoring_sessions (
                session_id TEXT PRIMARY KEY,
                start_time TEXT NOT NULL,
                end_time TEXT,
                duration_seconds INTEGER NOT NULL,
                total_packets INTEGER NOT NULL,
                total_bytes INTEGER NOT NULL,
                interface_name TEXT NOT NULL,
                capture_backend TEXT NOT NULL,
                security_findings_count INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS honeypot_interactions (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                service_type TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                client_port INTEGER NOT NULL,
                request_method TEXT,
                path TEXT,
                probe_summary TEXT NOT NULL,
                user_agent TEXT,
                payload_preview_sanitized TEXT,
                flagged_as_suspicious INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_honeypot_timestamp ON honeypot_interactions(timestamp DESC);

            CREATE TABLE IF NOT EXISTS dns_queries (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                query_name TEXT NOT NULL,
                record_type TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                server_ip TEXT NOT NULL,
                response_code TEXT,
                resolved_ips TEXT NOT NULL,
                latency_ms REAL,
                is_doh INTEGER NOT NULL,
                entropy_score REAL NOT NULL,
                is_suspicious INTEGER NOT NULL,
                threat_flags TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_dns_timestamp ON dns_queries(timestamp DESC);

            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value_json TEXT NOT NULL
            );
            "#,
        )?;

        Ok(())
    }

    /// Insert a security event
    pub fn insert_event(&self, event: &SecurityEvent) -> Result<()> {
        let conn = self.conn.lock();
        let evidence_json = serde_json::to_string(&event.supporting_evidence).unwrap_or_default();
        let steps_json = serde_json::to_string(&event.recommended_steps).unwrap_or_default();
        let category_str = serde_json::to_value(&event.category)
            .map(|v| v.as_str().unwrap_or("unknown").to_string())
            .unwrap_or_default();
        let severity_str = serde_json::to_value(&event.severity)
            .map(|v| v.as_str().unwrap_or("informational").to_string())
            .unwrap_or_default();
        let status_str = serde_json::to_value(&event.status)
            .map(|v| v.as_str().unwrap_or("active").to_string())
            .unwrap_or_default();

        conn.execute(
            r#"
            INSERT OR REPLACE INTO security_events (
                event_id, timestamp, rule_id, rule_name, category, severity,
                source_ip, source_port, dest_ip, dest_port, protocol, interface_name,
                what_observed, why_flagged, supporting_evidence, uncertainty_details,
                confidence_score, recommended_steps, status, user_notes, resolved_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)
            "#,
            params![
                event.event_id,
                event.timestamp,
                event.rule_id,
                event.rule_name,
                category_str,
                severity_str,
                event.source_ip,
                event.source_port,
                event.dest_ip,
                event.dest_port,
                event.protocol,
                event.interface_name,
                event.what_observed,
                event.why_flagged,
                evidence_json,
                event.uncertainty_details,
                event.confidence_score,
                steps_json,
                status_str,
                event.user_notes,
                event.resolved_at,
            ],
        )?;

        Ok(())
    }

    /// Query security events with filtering
    pub fn get_events(&self, filter: Option<&EventFilterCriteria>, limit: usize) -> Result<Vec<SecurityEvent>> {
        let conn = self.conn.lock();
        let mut query = "SELECT event_id, timestamp, rule_id, rule_name, category, severity,
                                source_ip, source_port, dest_ip, dest_port, protocol, interface_name,
                                what_observed, why_flagged, supporting_evidence, uncertainty_details,
                                confidence_score, recommended_steps, status, user_notes, resolved_at
                         FROM security_events WHERE 1=1".to_string();

        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(f) = filter {
            if let Some(ref search) = f.search_query {
                if !search.trim().is_empty() {
                    query.push_str(" AND (rule_name LIKE ? OR what_observed LIKE ? OR why_flagged LIKE ? OR source_ip LIKE ? OR dest_ip LIKE ?)");
                    let s = format!("%{}%", search.trim());
                    params.push(Box::new(s.clone()));
                    params.push(Box::new(s.clone()));
                    params.push(Box::new(s.clone()));
                    params.push(Box::new(s.clone()));
                    params.push(Box::new(s));
                }
            }
            if let Some(ref ip) = f.ip_address {
                if !ip.trim().is_empty() {
                    query.push_str(" AND (source_ip = ? OR dest_ip = ?)");
                    params.push(Box::new(ip.clone()));
                    params.push(Box::new(ip.clone()));
                }
            }
        }

        query.push_str(" ORDER BY timestamp DESC LIMIT ?");
        params.push(Box::new(limit as i64));

        let params_slice: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();

        let mut stmt = conn.prepare(&query)?;
        let rows = stmt.query_map(&params_slice[..], |row| {
            let cat_str: String = row.get(4)?;
            let sev_str: String = row.get(5)?;
            let evidence_json: String = row.get(14)?;
            let steps_json: String = row.get(17)?;
            let status_str: String = row.get(18)?;

            let category = serde_json::from_value(serde_json::Value::String(cat_str))
                .unwrap_or(crate::models::EventCategory::PortScan);
            let severity = serde_json::from_value(serde_json::Value::String(sev_str))
                .unwrap_or(EventSeverity::Informational);
            let status = serde_json::from_value(serde_json::Value::String(status_str))
                .unwrap_or(EventStatus::Active);

            let evidence = serde_json::from_str(&evidence_json).unwrap_or_default();
            let steps = serde_json::from_str(&steps_json).unwrap_or_default();

            Ok(SecurityEvent {
                event_id: row.get(0)?,
                timestamp: row.get(1)?,
                rule_id: row.get(2)?,
                rule_name: row.get(3)?,
                category,
                severity,
                source_ip: row.get(6)?,
                source_port: row.get(7)?,
                dest_ip: row.get(8)?,
                dest_port: row.get(9)?,
                protocol: row.get(10)?,
                interface_name: row.get(11)?,
                what_observed: row.get(12)?,
                why_flagged: row.get(13)?,
                supporting_evidence: evidence,
                uncertainty_details: row.get(15)?,
                confidence_score: row.get(16)?,
                recommended_steps: steps,
                status,
                user_notes: row.get(19)?,
                resolved_at: row.get(20)?,
            })
        })?;

        let mut events = Vec::new();
        for r in rows {
            if let Ok(e) = r {
                // Apply in-memory severity/status filtering if present
                if let Some(f) = filter {
                    if let Some(ref sevs) = f.severity {
                        if !sevs.contains(&e.severity) {
                            continue;
                        }
                    }
                    if let Some(ref stats) = f.status {
                        if !stats.contains(&e.status) {
                            continue;
                        }
                    }
                }
                events.push(e);
            }
        }

        Ok(events)
    }

    /// Update status of an event (resolve / dismiss without deleting)
    pub fn update_event_status(&self, event_id: &str, status: EventStatus, notes: Option<&str>) -> Result<bool> {
        let conn = self.conn.lock();
        let status_str = serde_json::to_value(&status)
            .map(|v| v.as_str().unwrap_or("active").to_string())
            .unwrap_or_default();
        let resolved_at = if status == EventStatus::Resolved || status == EventStatus::Dismissed {
            Some(Utc::now().to_rfc3339())
        } else {
            None
        };

        let rows = conn.execute(
            "UPDATE security_events SET status = ?1, user_notes = COALESCE(?2, user_notes), resolved_at = ?3 WHERE event_id = ?4",
            params![status_str, notes, resolved_at, event_id],
        )?;

        Ok(rows > 0)
    }

    /// Insert honeypot interaction
    pub fn insert_honeypot_log(&self, log: &HoneypotInteractionLog) -> Result<()> {
        let conn = self.conn.lock();
        let svc_str = serde_json::to_value(&log.service_type)
            .map(|v| v.as_str().unwrap_or("http_decoy").to_string())
            .unwrap_or_default();

        conn.execute(
            r#"
            INSERT OR REPLACE INTO honeypot_interactions (
                id, timestamp, service_type, client_ip, client_port, request_method,
                path, probe_summary, user_agent, payload_preview_sanitized, flagged_as_suspicious
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            "#,
            params![
                log.id,
                log.timestamp,
                svc_str,
                log.client_ip,
                log.client_port,
                log.request_method,
                log.path,
                log.probe_summary,
                log.user_agent,
                log.payload_preview_sanitized,
                if log.flagged_as_suspicious { 1 } else { 0 },
            ],
        )?;

        Ok(())
    }

    pub fn get_honeypot_logs(&self, limit: usize) -> Result<Vec<HoneypotInteractionLog>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, service_type, client_ip, client_port, request_method,
                    path, probe_summary, user_agent, payload_preview_sanitized, flagged_as_suspicious
             FROM honeypot_interactions ORDER BY timestamp DESC LIMIT ?"
        )?;

        let rows = stmt.query_map(params![limit as i64], |row| {
            let svc_str: String = row.get(2)?;
            let service_type = serde_json::from_value(serde_json::Value::String(svc_str))
                .unwrap_or(crate::models::HoneypotServiceType::HttpDecoy);
            let flagged: i64 = row.get(10)?;

            Ok(HoneypotInteractionLog {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                service_type,
                client_ip: row.get(3)?,
                client_port: row.get(4)?,
                request_method: row.get(5)?,
                path: row.get(6)?,
                probe_summary: row.get(7)?,
                user_agent: row.get(8)?,
                payload_preview_sanitized: row.get(9)?,
                flagged_as_suspicious: flagged != 0,
            })
        })?;

        let mut list = Vec::new();
        for r in rows.flatten() {
            list.push(r);
        }
        Ok(list)
    }

    /// Insert DNS query
    pub fn insert_dns_query(&self, q: &DnsQueryRecord) -> Result<()> {
        let conn = self.conn.lock();
        let resolved_json = serde_json::to_string(&q.resolved_ips).unwrap_or_default();
        let flags_json = serde_json::to_string(&q.threat_flags).unwrap_or_default();

        conn.execute(
            r#"
            INSERT OR REPLACE INTO dns_queries (
                id, timestamp, query_name, record_type, client_ip, server_ip,
                response_code, resolved_ips, latency_ms, is_doh, entropy_score,
                is_suspicious, threat_flags
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
            "#,
            params![
                q.id,
                q.timestamp,
                q.query_name,
                q.record_type,
                q.client_ip,
                q.server_ip,
                q.response_code,
                resolved_json,
                q.latency_ms,
                if q.is_doh_or_encrypted { 1 } else { 0 },
                q.entropy_score,
                if q.is_suspicious { 1 } else { 0 },
                flags_json,
            ],
        )?;

        Ok(())
    }

    pub fn get_dns_queries(&self, limit: usize) -> Result<Vec<DnsQueryRecord>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, query_name, record_type, client_ip, server_ip,
                    response_code, resolved_ips, latency_ms, is_doh, entropy_score,
                    is_suspicious, threat_flags
             FROM dns_queries ORDER BY timestamp DESC LIMIT ?"
        )?;

        let rows = stmt.query_map(params![limit as i64], |row| {
            let res_json: String = row.get(7)?;
            let flags_json: String = row.get(12)?;
            let is_doh: i64 = row.get(9)?;
            let is_susp: i64 = row.get(11)?;

            Ok(DnsQueryRecord {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                query_name: row.get(2)?,
                record_type: row.get(3)?,
                client_ip: row.get(4)?,
                server_ip: row.get(5)?,
                response_code: row.get(6)?,
                resolved_ips: serde_json::from_str(&res_json).unwrap_or_default(),
                latency_ms: row.get(8)?,
                is_doh_or_encrypted: is_doh != 0,
                entropy_score: row.get(10)?,
                is_suspicious: is_susp != 0,
                threat_flags: serde_json::from_str(&flags_json).unwrap_or_default(),
            })
        })?;

        let mut list = Vec::new();
        for r in rows.flatten() {
            list.push(r);
        }
        Ok(list)
    }

    /// Record completed or active monitoring session
    pub fn save_session(&self, stats: &SessionStats) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            r#"
            INSERT OR REPLACE INTO monitoring_sessions (
                session_id, start_time, duration_seconds, total_packets, total_bytes,
                interface_name, capture_backend, security_findings_count
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                stats.session_id,
                stats.start_time,
                stats.duration_seconds,
                stats.total_packets,
                stats.total_bytes,
                stats.interface_name,
                stats.capture_backend,
                stats.security_findings_total,
            ],
        )?;
        Ok(())
    }

    /// User-controlled purge or automatic retention cleanup
    pub fn purge_database(&self, retention_days: Option<u32>) -> Result<usize> {
        let conn = self.conn.lock();
        let total_deleted = if let Some(days) = retention_days {
            let cutoff = Utc::now() - chrono::Duration::days(days as i64);
            let cutoff_str = cutoff.to_rfc3339();

            let d1 = conn.execute("DELETE FROM security_events WHERE timestamp < ?1 AND status IN ('resolved', 'dismissed')", params![cutoff_str])?;
            let d2 = conn.execute("DELETE FROM honeypot_interactions WHERE timestamp < ?1", params![cutoff_str])?;
            let d3 = conn.execute("DELETE FROM dns_queries WHERE timestamp < ?1", params![cutoff_str])?;
            d1 + d2 + d3
        } else {
            // Full purge requested by user
            let d1 = conn.execute("DELETE FROM security_events", [])?;
            let d2 = conn.execute("DELETE FROM honeypot_interactions", [])?;
            let d3 = conn.execute("DELETE FROM dns_queries", [])?;
            let d4 = conn.execute("DELETE FROM monitoring_sessions", [])?;
            d1 + d2 + d3 + d4
        };

        // VACUUM to reclaim local disk space
        conn.execute("VACUUM", []).ok();

        Ok(total_deleted)
    }

    /// Export sanitized events as JSON
    pub fn export_events_json(&self) -> Result<String> {
        let events = self.get_events(None, 1000)?;
        Ok(serde_json::to_string_pretty(&events).unwrap_or_else(|_| "[]".to_string()))
    }

    /// Export sanitized events as CSV
    pub fn export_events_csv(&self) -> Result<String> {
        let events = self.get_events(None, 1000)?;
        let mut csv = String::from("event_id,timestamp,rule_id,rule_name,category,severity,source_ip,source_port,dest_ip,dest_port,protocol,status,confidence\n");
        for e in events {
            let cat_str = serde_json::to_value(&e.category).map(|v| v.as_str().unwrap_or("").to_string()).unwrap_or_default();
            let sev_str = serde_json::to_value(&e.severity).map(|v| v.as_str().unwrap_or("").to_string()).unwrap_or_default();
            let status_str = serde_json::to_value(&e.status).map(|v| v.as_str().unwrap_or("").to_string()).unwrap_or_default();

            csv.push_str(&format!(
                "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",{},\"{}\",{},\"{}\",\"{}\",{:.2}\n",
                e.event_id,
                e.timestamp,
                e.rule_id,
                e.rule_name.replace('"', "\"\""),
                cat_str,
                sev_str,
                e.source_ip.unwrap_or_default(),
                e.source_port.unwrap_or(0),
                e.dest_ip.unwrap_or_default(),
                e.dest_port.unwrap_or(0),
                e.protocol.unwrap_or_default(),
                status_str,
                e.confidence_score
            ));
        }
        Ok(csv)
    }
}
