// SHADOWSENTRY Core Desktop Application
// "Invisible Threats. Visible Intelligence."

pub mod capture;
pub mod commands;
pub mod database;
pub mod detection;
pub mod honeypot;
pub mod models;
pub mod network;
pub mod packet;

use capture::CaptureManager;
use commands::AppState;
use database::DatabaseManager;
use detection::DetectionEngine;
use honeypot::HoneypotLabManager;
use models::AppSettings;
use parking_lot::Mutex;
use std::sync::Arc;

pub fn run() {
    // Initialize SQLite database
    let db = match DatabaseManager::new() {
        Ok(d) => Arc::new(d),
        Err(e) => {
            eprintln!("Warning: Failed to open persistent DB ({}), using in-memory: {}", e, e);
            Arc::new(DatabaseManager::new_in_memory().expect("In-memory database failed"))
        }
    };

    let settings = AppSettings::default();
    let detection = Arc::new(DetectionEngine::new(settings.thresholds.clone()));
    let capture = Arc::new(CaptureManager::new(Arc::clone(&db), Arc::clone(&detection)));
    let honeypot = Arc::new(HoneypotLabManager::new(Arc::clone(&db), Arc::clone(&detection)));

    let state = AppState {
        database: db,
        detection,
        capture: Arc::clone(&capture),
        honeypot: Arc::clone(&honeypot),
        settings: Mutex::new(settings),
    };

    let capture_cleanup = Arc::clone(&capture);
    let honeypot_cleanup = Arc::clone(&honeypot);

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            commands::get_monitoring_status,
            commands::start_monitoring,
            commands::stop_monitoring,
            commands::get_network_interfaces,
            commands::get_capture_driver_status,
            commands::get_gateway_info,
            commands::get_arp_table,
            commands::get_live_packets,
            commands::get_dns_queries,
            commands::get_security_events,
            commands::update_event_status,
            commands::get_honeypot_status,
            commands::start_honeypot_service,
            commands::stop_honeypot_service,
            commands::get_honeypot_logs,
            commands::get_session_stats,
            commands::get_traffic_timeline,
            commands::get_protocol_distribution,
            commands::get_severity_distribution,
            commands::get_app_settings,
            commands::save_app_settings,
            commands::purge_database,
            commands::export_events_json,
            commands::export_events_csv,
            commands::run_lab_scenario,
            commands::simulate_honeypot_probe,
        ])
        .on_window_event(move |_window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                capture_cleanup.stop_monitoring();
                honeypot_cleanup.stop_all();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running shadowsentry application");
}
