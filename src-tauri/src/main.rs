// SHADOWSENTRY Desktop Application Entry
// "Invisible Threats. Visible Intelligence."

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    shadowsentry_lib::run();
}
