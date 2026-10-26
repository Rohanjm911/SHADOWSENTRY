# System Architecture — SHADOWSENTRY

**SHADOWSENTRY: Invisible Threats. Visible Intelligence.**  
*Native Desktop Network Security Application for Windows 10 and Windows 11*

---

## 1. High-Level Architectural Model

SHADOWSENTRY is divided into four strictly segregated architectural tiers:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        FRONTEND PRESENTATION LAYER                     │
│  React 18 • TypeScript • CSS Tokens • SVG Charts • Virtualized Tables  │
│  Pages: Dashboard, Live Traffic, DNS Monitor, Threat Center,           │
│         Honeypot Lab, Event History, Executive Reports, Settings       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                        Tauri 2 IPC JSON-RPC Bridge
               (Narrowly Scoped Command Manifest, Zero-Shell)
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│                       TAURI APPLICATION COMMAND LAYER                  │
│  `src-tauri/src/commands/mod.rs` (25 Registered Handlers)               │
│  Interface Discovery • Capture Lifecycle • Rule Thresholds • DB Queries│
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                               In-Memory State
                         (Arc<RwLock<AppState>>, Bus)
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│                          RUST SECURITY CORE                            │
│                                                                        │
│  ┌────────────────────┐  ┌────────────────────┐  ┌───────────────────┐ │
│  │  Capture Engine    │  │ Zero-Panic Parser  │  │ Detection Engine  │ │
│  │  - Npcap DLL       │  │  - L2: Ethernet    │  │  - 10 Explainable │ │
│  │  - Native Raw Sock │  │  - L3: IPv4 / IPv6 │  │    Rules          │ │
│  │  - Test Lab Mock   │  │  - L4: TCP / UDP   │  │  - Port Scans     │ │
│  │  - Ring Buffer     │  │  - L7: DNS Decoder │  │  - DNS DGAs       │ │
│  └────────────────────┘  └────────────────────┘  └───────────────────┘ │
│                                                                        │
│  ┌────────────────────┐  ┌────────────────────┐  ┌───────────────────┐ │
│  │ Honeypot Lab Mgr   │  │ Network Discovery  │  │ Local SQLite DB   │ │
│  │  - HTTP Decoy      │  │  - Win32 IP Helper │  │  - WAL Mode       │ │
│  │  - Admin Simulator │  │  - ARP NetTable2   │  │  - Retention Mgt  │ │
│  │  - SSH Banner      │  │  - Gateway Monitor │  │  - Sanitized Exp  │ │
│  └────────────────────┘  └────────────────────┘  └───────────────────┘ │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Component Subsystems

### 2.1. Capture Engine (`src-tauri/src/capture/mod.rs`)
- **Backend Hierarchy**:
  1. **Npcap Dynamic Driver (`wpcap.dll`)**: When present, loads Npcap functions via `libloading` for high-throughput packet capture and promiscous mode.
  2. **Windows Native Raw Sockets (`AF_INET, SOCK_RAW`)**: Built-in Windows socket fallback with `SIO_RCVALL` promiscuous binding when elevated without needing third-party drivers.
  3. **Laboratory Simulation Mode**: Generates realistic network packets (DNS bursts, SYN port scans, gateway changes, web traffic) for laboratory demonstration and offline verification without requiring driver installation.
- **Bounded Buffer**: A lock-free/bounded ring buffer retains a maximum of 5,000 recent packets (up to 64 MB), preventing unbounded memory growth.

### 2.2. Zero-Panic Packet Parser (`src-tauri/src/packet/mod.rs`)
- Strictly validated slicing ensures malformed frames, truncated IP options, or corrupt lengths never induce panics.
- Decodes Ethernet II, ARP, IPv4, IPv6, TCP (SYN/ACK/FIN/RST/PSH), UDP, and DNS query names, types, and Shannon entropy.
- Strips payload data immediately, storing only protocol metadata.

### 2.3. Explainable Detection Engine (`src-tauri/src/detection/mod.rs`)
Evaluates 10 deterministic forensic rules:
1. `RULE_PORT_SCAN`: Multi-port connection attempts from a single source within a sliding time window.
2. `RULE_TRAFFIC_BURST`: Sudden packet rate spikes exceeding configured packets-per-second thresholds.
3. `RULE_CONNECTION_FAILURE`: Repeated TCP RST responses indicating closed port probing or rejected handshakes.
4. `RULE_SUSPICIOUS_DNS`: High Shannon entropy domain names characteristic of Domain Generation Algorithms (DGA) or DNS tunneling.
5. `RULE_GATEWAY_CHANGE`: Default gateway IP or MAC address alterations during an active session.
6. `RULE_ARP_ANOMALY`: Conflicting IP-to-MAC associations detected in the ARP cache.
7. `RULE_THREAT_INTEL`: IP address matches against local user-configured threat intelligence indicators.
8. `RULE_HONEYPOT_PROBE`: Repeated connection or probe attempts directed at active honeypot ports.
9. `RULE_UNUSUAL_INBOUND`: Unsolicited inbound connection attempts targeting sensitive administrative ports (RDP, SSH, Telnet).
10. `RULE_CONFIG_CHANGE`: Monitoring configuration changes or capture engine parameter modifications.

### 2.4. Local Honeypot Lab (`src-tauri/src/honeypot/mod.rs`)
- Manages three independent simulated services: HTTP Decoy (Port 8080), Admin Portal (Port 8443), and SSH Banner Simulator (Port 2222).
- Default to `127.0.0.1` loopback binding.
- Restricts socket connections with strict timeouts (5s) and payload size ceilings (16 KB).
- Rejects client input, never executes commands, and never retains credentials.

### 2.5. Local SQLite Database (`src-tauri/src/database/mod.rs`)
- Resides at `%LOCALAPPDATA%\ShadowSentry\shadowsentry.db`.
- WAL (Write-Ahead Logging) mode enabled for high-concurrency read/write operations.
- Schema auto-migration on application launch.
- Provides sanitized JSON and CSV export endpoints with privacy-preserving redactions.
