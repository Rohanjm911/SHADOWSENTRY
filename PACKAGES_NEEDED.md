# Required Packages & Technology Stack

### *SHADOWSENTRY — Invisible Threats. Visible Intelligence.*

This document catalogs every system runtime, development tool, frontend package, and backend Rust crate required to build, run, test, and package **SHADOWSENTRY**, along with their official brand logos and installation instructions.

---

## 1. System & Runtime Prerequisites

These tools and runtimes are required on the host Windows machine to run or build the desktop application.

| Logo | Component | Version | Purpose | Download / Install |
| :---: | :--- | :---: | :--- | :--- |
| <img src="docs/assets/logos/windows.svg" width="30" height="30" alt="Windows 11"/> | **Windows 10 / 11 (x64)** | 64-bit | Target operating system. Leverages Windows Sockets 2, IP Helper API, and Win32 security tokens. | Pre-installed |
| <img src="docs/assets/logos/microsoftedge.svg" width="30" height="30" alt="Edge WebView2"/> | **Microsoft Edge WebView2** | Evergreen | Native desktop UI rendering engine embedded in Tauri 2 window frames. | [Download Runtime](https://developer.microsoft.com/en-us/microsoft-edge/webview2/) *(Pre-installed on Win 10/11)* |
| <img src="docs/assets/logos/rust.svg" width="30" height="30" alt="Rust"/> | **Rust Toolchain** | `1.75+` (stable) | Compiles the high-speed security core, packet parser, detection engine, and SQLite database. | `winget install Rustlang.Rustup` or [rustup.rs](https://rustup.rs) |
| <img src="docs/assets/logos/visualstudio.svg" width="30" height="30" alt="MSVC Build Tools"/> | **Visual Studio C++ Build Tools** | 2022+ | Provides `link.exe` and Windows SDK headers for the `x86_64-pc-windows-msvc` target. | `winget install Microsoft.VisualStudio.2022.BuildTools` |
| <img src="docs/assets/logos/nodedotjs.svg" width="30" height="30" alt="Node.js"/> | **Node.js & npm** | `v18+` (LTS) | Executes the frontend build pipeline, TypeScript compiler, and Vite bundler. | `winget install OpenJS.NodeJS.LTS` or [nodejs.org](https://nodejs.org) |
| <img src="docs/assets/logos/python.svg" width="30" height="30" alt="Python"/> | **Python 3** | `3.10+` | Executes automated test fixture generation and honeypot probe validation scripts. | `winget install Python.Python.3.12` or [python.org](https://python.org) |
| <img src="docs/assets/logos/wireshark.svg" width="30" height="30" alt="Npcap"/> | **Npcap Driver** *(Optional)* | `1.70+` | Enables promiscuous Layer-2 Ethernet frame capture via `wpcap.dll`. *(Not needed if running via Raw Sockets as Admin)*. | [npcap.com](https://npcap.com/#download) |
| <img src="docs/assets/logos/windows.svg" width="30" height="30" alt="WiX Toolset"/> | **WiX Toolset v3** *(Optional)* | `3.11+` | Generates official Windows `.msi` standalone installer packages. | `winget install WiX` or [wixtoolset.org](https://wixtoolset.org) |

---

## 2. Frontend Packages (Node.js / npm)

Located in [`package.json`](file:///d:/projects%20and%20certificates/projects/apps/Shadow%20Sentry/package.json). Power the responsive, dark-mode cybersecurity dashboard.

| Logo | Package | Version | Type | Purpose |
| :---: | :--- | :---: | :---: | :--- |
| <img src="docs/assets/logos/react.svg" width="30" height="30" alt="React"/> | **`react`** | `^18.3.1` | Runtime | Declarative UI component tree rendering and real-time state synchronization. |
| <img src="docs/assets/logos/react.svg" width="30" height="30" alt="React DOM"/> | **`react-dom`** | `^18.3.1` | Runtime | DOM mounting and synthetic event reconciliation for desktop webviews. |
| <img src="docs/assets/logos/tauri.svg" width="30" height="30" alt="Tauri API"/> | **`@tauri-apps/api`** | `^2.2.0` | Runtime | Type-safe IPC bridge for invoking Rust backend commands and listening to packet streams. |
| <img src="docs/assets/logos/lucide.svg" width="30" height="30" alt="Lucide Icons"/> | **`lucide-react`** | `^0.475.0` | Runtime | Technical, sharp desktop iconography for network statuses, alerts, and protocols. |
| <img src="docs/assets/logos/typescript.svg" width="30" height="30" alt="TypeScript"/> | **`typescript`** | `^5.7.3` | Dev | Static type safety across network packet models, alerts, and forensic query state. |
| <img src="docs/assets/logos/vite.svg" width="30" height="30" alt="Vite"/> | **`vite`** | `^6.1.0` | Dev | Fast frontend bundling and production optimization for local embedded assets. |
| <img src="docs/assets/logos/vite.svg" width="30" height="30" alt="Vite Plugin React"/> | **`@vitejs/plugin-react`** | `^4.3.4` | Dev | Fast Refresh and JSX transformation support for React 18 within Vite. |
| <img src="docs/assets/logos/tauri.svg" width="30" height="30" alt="Tauri CLI"/> | **`@tauri-apps/cli`** | `^2.2.0` | Dev | Build orchestration CLI for bundling Rust binaries and frontend dist assets into Windows `.exe`/`.msi`. |

---

## 3. Backend Crates (Rust / Cargo)

Located in [`src-tauri/Cargo.toml`](file:///d:/projects%20and%20certificates/projects/apps/Shadow%20Sentry/src-tauri/Cargo.toml). Handles high-throughput packet processing, SQLite storage, and Win32 OS APIs.

| Logo | Crate | Version | Purpose |
| :---: | :--- | :---: | :--- |
| <img src="docs/assets/logos/tauri.svg" width="30" height="30" alt="Tauri"/> | **`tauri`** | `2` | Application lifecycle, native Windows window management, and secure IPC command handlers. |
| <img src="docs/assets/logos/rust.svg" width="30" height="30" alt="Tokio"/> | **`tokio`** | `1` (full) | Asynchronous multi-threaded runtime powering background packet sniffing, honeypots, and timer loops. |
| <img src="docs/assets/logos/sqlite.svg" width="30" height="30" alt="SQLite"/> | **`rusqlite`** | `0.31` (bundled) | Embedded C SQLite3 engine with Write-Ahead Logging (WAL) for persistent forensic alerts and host caches. |
| <img src="docs/assets/logos/rust.svg" width="30" height="30" alt="Serde"/> | **`serde` & `serde_json`** | `1` | High-performance serialization of network packets, alert evidence, and IPC command payloads. |
| <img src="docs/assets/logos/windows_crate.svg" width="30" height="30" alt="Windows Sys"/> | **`windows-sys`** | `0.59` | Direct Win32 API bindings for Windows Sockets 2 (`AF_INET`, `SOCK_RAW`), IP Helper (`GetAdaptersAddresses`, `GetIpNetTable`), and process security. |
| <img src="docs/assets/logos/rust.svg" width="30" height="30" alt="Libloading"/> | **`libloading`** | `0.8` | Dynamic runtime loader that safely probes for `wpcap.dll` without crashing if Npcap is not installed. |
| <img src="docs/assets/logos/rust.svg" width="30" height="30" alt="Chrono"/> | **`chrono`** | `0.4` | High-precision microsecond timestamps for packet headers and forensic event timelines. |
| <img src="docs/assets/logos/rust.svg" width="30" height="30" alt="UUID"/> | **`uuid`** | `1` | Generates RFC 4122 v4 unique incident identifier tokens for explainable security alerts. |
| <img src="docs/assets/logos/rust.svg" width="30" height="30" alt="Parking Lot"/> | **`parking_lot`** | `0.12` | Low-overhead spinlock and synchronization primitives for bounded FIFO packet ring buffers. |
| <img src="docs/assets/logos/rust.svg" width="30" height="30" alt="Tracing"/> | **`tracing` & `tracing-subscriber`** | `0.1 / 0.3` | Structured, zero-allocation diagnostic logging for capture events and protocol errors. |

---

## 4. Quick Installation Commands

To set up the entire development environment from scratch on Windows:

```powershell
# 1. Install System Compilers & Runtimes (via winget)
winget install Rustlang.Rustup
winget install OpenJS.NodeJS.LTS
winget install Python.Python.3.12
winget install Microsoft.VisualStudio.2022.BuildTools

# 2. Clone repository & install frontend npm packages
cd "d:\projects and certificates\projects\apps\Shadow Sentry"
npm install

# 3. Verify Rust compiler
rustc --version
cargo --version
```
