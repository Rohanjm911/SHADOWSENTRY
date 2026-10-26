# Threat Model & Risk Analysis — SHADOWSENTRY

**SHADOWSENTRY: Invisible Threats. Visible Intelligence.**

---

## 1. System Assets & Security Objectives

SHADOWSENTRY monitors untrusted network environments. Its primary assets requiring protection are:

| Asset | Confidentiality | Integrity | Availability | Description |
| :--- | :---: | :---: | :---: | :--- |
| **Host System Integrity** | **Critical** | **Critical** | **Critical** | The host Windows 10/11 operating system must never be compromised by packet parsing or honeypot interactions. |
| **Network Stability** | Low | High | **Critical** | SHADOWSENTRY must not disrupt host network connectivity, leak credentials, or saturate host bandwidth. |
| **Local Security DB** | High | **Critical** | High | SQLite logs, detected events, and session metadata must not be tampered with or corrupted. |
| **User Privacy** | **Critical** | High | High | No raw application payloads or unobserved third-party traffic must be persisted or transmitted externally. |

---

## 2. Attack Surfaces & Threat Vectors

```
                                [ Untrusted Network / Attacker ]
                                                │
                          ┌─────────────────────┴─────────────────────┐
                          │                                           │
                          ▼                                           ▼
             [ Attack Vector 1: Malformed Packets ]       [ Attack Vector 2: Honeypot Exploitation ]
                          │                                           │
                          ▼                                           ▼
             [ Rust Zero-Panic Parser ]                  [ Safe Loopback Honeypot Lab ]
                          │                                           │
                          └─────────────────────┬─────────────────────┘
                                                │
                                                ▼
                                   [ Local SQLite Database ]
                                                │
                                                ▼
                                  [ Tauri 2 IPC Command Layer ]
                                                │
                                                ▼
                                   [ Hardened React UI Shell ]
```

### Threat Vector 1: Malformed Packet Denial of Service / RCE
- **Threat**: An attacker on the local network transmits crafted Ethernet, IP, TCP, or DNS packets with corrupt header lengths, invalid fragmentation flags, or cyclic DNS pointers attempting to cause memory corruption or a denial-of-service crash.
- **Mitigation**:
  - Safe Rust implementation with strict bounds checks on all packet slices.
  - Zero `unsafe` pointer arithmetic in the parser module.
  - Bounded ring buffer discarding excess packets when saturation occurs.
  - Zero-panic contract: malformed frames return a structured parsing error and are accounted for in telemetry without aborting the capture loop.

### Threat Vector 2: Honeypot Service Exploitation & Network Pivoting
- **Threat**: An attacker identifies the honeypot port (e.g. 8080, 8443, 2222) and submits remote code execution payloads (e.g., Log4Shell, command injection, path traversal) or attempts to use the honeypot as an open proxy/pivot into the internal LAN.
- **Mitigation**:
  - Default loopback binding (`127.0.0.1`). Exposing to `0.0.0.0` requires explicit confirmation.
  - Simulated protocols only: no shell interpreter, no `cmd.exe`/`powershell.exe` execution, and no SQL backend in the honeypot servers.
  - Strict input ceilings: Maximum 16 KB request body; excess bytes are dropped.
  - Sockets do not forward or proxy traffic to any internal or external destinations.
  - Passwords and auth tokens are immediately discarded to prevent credential leaks.

### Threat Vector 3: IPC Injection / Privilege Escalation via UI
- **Threat**: Malicious scripts injected into the webview attempt to call privileged OS commands or write arbitrary files.
- **Mitigation**:
  - Restrictive Tauri 2 capability configuration (`src-tauri/capabilities/default.json`).
  - No arbitrary shell execution or filesystem access exposed to the frontend.
  - All database queries and configuration updates undergo validation within Rust handlers.
  - CSP configured to block inline scripts from untrusted external sources.

---

## 3. Residual Risks & Out-of-Scope Threats

1. **Kernel-Level Rootkits**: If the Windows operating system is compromised at the kernel level (Ring 0), an attacker can subvert NDIS packet capture drivers or manipulate the Windows IP Helper table.
2. **Encrypted Protocol Invisibility**: Modern encrypted protocols (DoH, DoT, TLS 1.3, WireGuard) conceal application-layer metadata by design. SHADOWSENTRY legitimately reports this boundary rather than performing risky TLS MITM decryption.
3. **Hardware Switched Network Isolation**: On a switched network without port mirroring (SPAN), unicast packets between two other nodes do not traverse the host NIC. SHADOWSENTRY cannot observe traffic outside its broadcast domain or promiscuous route.
