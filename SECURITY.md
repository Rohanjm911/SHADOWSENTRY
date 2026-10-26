# Security Policy & Architecture Guidelines — SHADOWSENTRY

**SHADOWSENTRY: Invisible Threats. Visible Intelligence.**

---

## 1. Vulnerability Reporting Policy

The SHADOWSENTRY team takes the security and integrity of desktop network monitoring seriously. If you identify a security vulnerability or exploit vector in SHADOWSENTRY:
1. **Do not create a public issue**.
2. Report the vulnerability to the security contacts specified in the project repository or email: `security@shadowsentry.local`.
3. Provide:
   - Specific component or module affected (e.g., Honeypot HTTP Decoy, Packet Parser, IPC Command).
   - Minimal reproduction proof-of-concept.
   - Operating system version (Windows 10 / Windows 11 x64) and capture driver state (Npcap installed / native fallback).

We commit to validating and addressing vulnerabilities within 72 hours.

---

## 2. Threat Model & Security Boundaries

SHADOWSENTRY operates on an untrusted network boundary by its very nature as a network sniffer and honeypot simulator. The architecture implements strict defense-in-depth:

```
[ Untrusted Network Traffic / Packets ]
              │
              ▼
   ┌────────────────────────────────────────────────────────┐
   │ Bounded Native Ring Buffer (Max 5,000 pkts / 64MB)     │
   └──────────────────────────┬─────────────────────────────┘
                              │
                              ▼
   ┌────────────────────────────────────────────────────────┐
   │ Zero-Panic Rust Packet Parser (No unsafe memory ops)  │
   │  - Bounded slice slicing, checked length invariants    │
   │  - Automatic payload discard (headers only)            │
   └──────────────────────────┬─────────────────────────────┘
                              │
                              ▼
   ┌────────────────────────────────────────────────────────┐
   │ Deterministic Heuristic Detection Engine (Rust)        │
   │  - Explainable rules, bounded slide-windows            │
   └──────────────────────────┬─────────────────────────────┘
                              │
                              ▼
   ┌────────────────────────────────────────────────────────┐
   │ Local-Only SQLite Database (WAL mode, non-admin)       │
   └──────────────────────────┬─────────────────────────────┘
                              │
                              ▼
   ┌────────────────────────────────────────────────────────┐
   │ Restrictive Tauri 2 IPC Command Boundary               │
   │  - Scoped commands, no shell exec, no arbitrary fs     │
   └──────────────────────────┬─────────────────────────────┘
                              │
                              ▼
   ┌────────────────────────────────────────────────────────┐
   │ Hardened React Desktop GUI (No external CDN/resources) │
   └────────────────────────────────────────────────────────┘
```

---

## 3. Defense-in-Depth Mechanisms

### 3.1. Zero-Panic Parsing Guarantee
All network packet parsing (Ethernet, ARP, IPv4, IPv6, TCP, UDP, DNS) is implemented in safe Rust with explicit bounds-checking and zero unchecked memory arithmetic. Malformed packets, corrupted length headers, truncated frames, or invalid checksums are rejected cleanly and logged without crashing the background worker.

### 3.2. Principle of Least Privilege
- **Non-Admin Default**: SHADOWSENTRY runs as a standard desktop user. Elevated privileges are never required merely to view historical events, inspect reports, or run the UI.
- **Capture Elevation Boundaries**: When capturing via Windows Raw Sockets (`AF_INET, SOCK_RAW`), Windows requires administrator elevation. SHADOWSENTRY clearly displays an `Elevation Required` notice in the UI rather than silently attempting privilege escalation.
- **Npcap Driver Isolation**: When Npcap is used, capture is performed via Npcap's signed driver (`npf.sys`) adhering to the Windows NDIS filter model. SHADOWSENTRY never attempts silent driver installation.

### 3.3. Local Honeypot Containment & Safety
The Local Honeypot Lab is an opt-in simulated environment for controlled threat detection. It is designed to prevent host compromise:
1. **Loopback Binding by Default**: All honeypot services (`HTTP Decoy`, `Admin Portal`, `SSH Banner`) bind strictly to `127.0.0.1`.
2. **Explicit LAN Confirmation**: Binding to `0.0.0.0` (all local network interfaces) requires explicit user confirmation in a high-risk confirmation modal.
3. **No Command Execution**: The honeypot simulators **never execute shell commands, eval scripts, or spawn sub-processes** based on client input.
4. **Credential Dropping**: Submitted passwords, tokens, or authorization headers are parsed purely to record `interaction_count` and probe presence; actual cleartext credentials are immediately zeroized and never saved to disk.
5. **Anti-Pivot Safeguards**: The honeypot modules never initiate outbound connections, forward network sockets, or proxy requests, preventing an attacker from using SHADOWSENTRY as a pivot.
6. **Bounded Resource Quotas**:
   - Max 10 concurrent connections.
   - Max 16 KB request body size (excess dropped).
   - Strict 5-second socket read/write timeouts.

---

## 4. Tauri IPC Hardening

The desktop bridge between the React frontend and Rust backend is strictly locked down:
- **No Remote Content**: The desktop shell loads all HTML, CSS, and JS from the local binary bundle. No third-party CDNs, external scripts, or fonts are fetched over the network.
- **Scoped Commands**: Only the 25 explicitly declared Tauri commands in `src-tauri/capabilities/default.json` are exposed.
- **No Arbitrary Shell or Filesystem Access**: The frontend cannot read or write arbitrary files, execute shell commands, or modify registry keys. All file exports are handled strictly by backend file-dialog routines.

---

## 5. Network Firewall Integrity
SHADOWSENTRY **does not modify Windows Firewall rules automatically**. If a user explicitly chooses to expose a honeypot port to the LAN, the application clearly explains which port and protocol must be allowed in the Windows Defender Firewall and requests manual administrator authorization.
