# Privacy Policy & Architecture Guarantees — SHADOWSENTRY

**SHADOWSENTRY: Invisible Threats. Visible Intelligence.**  
*Last Updated: October 2026*

SHADOWSENTRY is designed from the ground up as a **local-first, privacy-respecting network investigation and threat detection desktop application** for Windows 10 and Windows 11.

---

## 1. Core Privacy Commitments

1. **Zero External Telemetry**:
   SHADOWSENTRY does not contain any analytics SDKs, error reporting telemetry (e.g., Sentry, Bugsnag), phone-home beacons, or user tracking services.
2. **Zero Cloud Dependencies**:
   There are no mandatory accounts, logins, API keys, or cloud servers required to operate the application. All detection logic, parsing, and analysis execute locally on your computer.
3. **Local-Only Storage**:
   All captured session metadata, security events, and configuration profiles are stored exclusively on your local machine in an SQLite database located at:
   `%LOCALAPPDATA%\ShadowSentry\shadowsentry.db`.
4. **Metadata-Only by Default**:
   SHADOWSENTRY captures protocol headers and connection metadata (IP addresses, ports, protocol types, TCP flags, packet lengths, observable DNS domain names). **Raw application layer payloads (e.g., HTTP bodies, TLS application data, email content) are discarded by default.**

---

## 2. Data Collection Boundaries

| Data Type | Collected By Default? | Storage Location | Retention / Redaction |
| :--- | :--- | :--- | :--- |
| **Layer 2/3/4 Headers** (IP, Port, Flags) | Yes (Session Metadata) | SQLite DB (Bounded ring buffer) | Configurable retention (default: 30 days) |
| **Observable DNS Queries** (UDP/TCP 53) | Yes (Query name, Type) | SQLite DB (`security_events`) | Domain name and Shannon entropy only |
| **Application Layer Payloads** | **No** | Discarded in memory | Disabled by default in settings |
| **Passphrases & Credentials** | **No** | Never collected or stored | Honeypot modules explicitly drop client input |
| **System Info & Network Adapters** | Yes (Local display only) | In-memory query | Never persisted beyond interface selection |
| **Gateway MAC & ARP Tables** | Yes (Anomaly detection) | SQLite DB & In-memory cache | Stored locally for ARP conflict detection |

---

## 3. Threat Detection Explainability & Uncertainty

SHADOWSENTRY adheres to strict forensic transparency:
- It **never claims an attack is proven** based solely on statistical heuristics.
- Every detected event explicitly states:
  - **What was observed** (exact packet timestamp, IP endpoints, protocol).
  - **Which rule triggered** (transparent deterministic logic, e.g., port scan threshold).
  - **What remains uncertain** (e.g., benign network scanner vs. malicious actor).
  - **Recommended manual investigation steps**.

---

## 4. User Controls & Forensic Data Management

### 4.1. Sanitized Data Export
You can export security events and monitoring sessions to **Sanitized JSON** or **Sanitized CSV**:
- Payloads are excluded.
- Internal database row IDs and sensitive system paths are stripped.
- Timestamps are formatted in ISO-8601 UTC.
- Evidence fields contain only relevant forensic connection metadata.

### 4.2. Forensic Data Purge
Under **Settings -> Storage & Retention Management**:
- You can change data retention from 1 to 365 days.
- You can execute **"Purge All Security Events"** or **"Wipe Entire Database"** at any time.
- Deletion executes a cryptographically clean `DELETE FROM table; VACUUM;` sequence in SQLite, reclaiming disk space immediately.

---

## 5. Network Protocol Limitations & Encrypted Traffic

SHADOWSENTRY respects user privacy boundaries imposed by modern operating systems and protocols:
- **Encrypted DNS (DoH / DoT)**: Queries transmitted over HTTPS (port 443) or TLS (port 853) are encrypted by design. SHADOWSENTRY cannot and does not inspect encrypted TLS traffic.
- **Switched Networks**: On Ethernet switches and Wi-Fi networks with client isolation, a standard workstation adapter can only observe unicast traffic directed to or from its own MAC address, alongside broadcast/multicast packets.
- **VPN Tunnels**: Traffic routed through encrypted VPN adapters (WireGuard, OpenVPN, IPsec) cannot be inspected prior to encryption without TAP/TUN adapter hooks.

---

## 6. Verification & Auditing

SHADOWSENTRY's desktop shell (Tauri 2) strictly prohibits arbitrary external network requests. All source code for the Rust backend and React frontend is open and auditable under the MIT License.
