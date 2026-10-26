# Windows Requirements & Driver Integration — SHADOWSENTRY

**SHADOWSENTRY: Invisible Threats. Visible Intelligence.**

---

## 1. Supported Operating Systems

- **Windows 11 (64-bit)**: 21H2, 22H2, 23H2, and subsequent releases.
- **Windows 10 (64-bit)**: 20H2, 21H1, 21H2, 22H2.
- Architecture: `x86_64` (AMD64).

---

## 2. Windows Runtime Components

SHADOWSENTRY relies on native Windows APIs and the Microsoft WebView2 runtime:
1. **Microsoft Edge WebView2 Runtime**:
   - Pre-installed on Windows 11 and Windows 10 (via Windows Update).
   - Used by Tauri 2 to render the hardened React interface within `msedgewebview2.exe`.
2. **Windows IP Helper API (`iphlpapi.dll`)**:
   - Native Windows system library (present on all Windows versions).
   - Used for non-privileged network adapter enumeration (`GetAdaptersAddresses`), ARP table inspection (`GetIpNetTable2`), and gateway routing queries.
3. **Windows Sockets 2 (`ws2_32.dll`)**:
   - Used for socket creation, TCP/UDP port binding, and raw socket captures.

---

## 3. Packet Capture Backends

SHADOWSENTRY implements a tiered capture strategy:

```
                              ┌─────────────────────────────┐
                              │     Start Capture Invoked   │
                              └──────────────┬──────────────┘
                                             │
                          Is Npcap (wpcap.dll) available?
                                    /               \
                                 YES                 NO
                                 /                     \
                   ┌────────────────────────┐    Is application elevated
                   │  Npcap Driver Mode     │    (Administrator)?
                   │  (High throughput,     │          /         \
                   │   Promiscuous L2-L7)   │       YES           NO
                   └────────────────────────┘       /               \
                                    ┌──────────────────────┐  ┌───────────────────────┐
                                    │ Windows Raw Sockets  │  │ Non-Elevated Fallback │
                                    │ (SIO_RCVALL IP layer)│  │ (Lab Mode & Stats)    │
                                    └──────────────────────┘  └───────────────────────┘
```

### 3.1. Backend 1: Npcap (Recommended)
- **Description**: The industry standard Windows packet capture architecture developed by the Nmap project.
- **Capabilities**:
  - Full Layer-2 Ethernet frame capture.
  - ARP packet inspection and spoofing detection.
  - Promiscuous mode support on supported Wi-Fi and Ethernet NICs.
- **Installation**:
  - Download official installer from: `https://npcap.com/#download`.
  - Install with **"WinPcap API-compatible Mode"** enabled (installs `wpcap.dll` and `Packet.dll` into `System32` or `System32\Npcap`).
  - *Note*: SHADOWSENTRY **never installs drivers silently**. Users must install Npcap with official administrative approval.

### 3.2. Backend 2: Windows Native Raw Sockets
- **Description**: Windows Sockets 2 `AF_INET` raw socket with `SIO_RCVALL` ioctl.
- **Capabilities**:
  - Captures incoming and outgoing IPv4 and IPv6 packets without requiring third-party drivers.
  - Extracts TCP, UDP, and DNS metadata.
- **Limitations**:
  - Does not capture Layer-2 Ethernet headers or raw ARP frames (Windows kernel drops ARP before raw IP sockets).
  - Requires running SHADOWSENTRY as Administrator (Windows security policy restricts raw sockets to elevated tokens).

### 3.3. Backend 3: Laboratory & Non-Elevated Safe Mode
- When neither Npcap nor Administrator privileges are present:
  - SHADOWSENTRY remains fully operational for interface inspection, gateway monitoring, and viewing past records.
  - Includes an integrated **Laboratory Scenario Engine** capable of injecting realistic test traffic (port scans, DNS bursts, honeypot probes) for authorized training and security evaluation.

---

## 4. Windows Firewall & Honeypot Reachability

- By default, SHADOWSENTRY honeypot modules bind to `127.0.0.1` (loopback). Loopback connections are permitted by the Windows Firewall without prompts.
- If a user explicitly chooses to bind honeypot services to `0.0.0.0` to monitor LAN probes:
  - The Windows Defender Firewall may display an alert: *"Windows Defender Firewall has blocked some features of this app"*.
  - The user must explicitly click **"Allow access"** on Private networks to allow inbound probes on ports 8080 (HTTP Decoy), 8443 (Admin Portal), or 2222 (SSH Banner).
  - SHADOWSENTRY **never silently modifies Windows Firewall rules**.
