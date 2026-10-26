# Local Honeypot Lab Guide — SHADOWSENTRY

**SHADOWSENTRY: Invisible Threats. Visible Intelligence.**

---

## 1. Laboratory Purpose & Concept

The **Local Honeypot Lab** is an opt-in, controlled security environment embedded directly within SHADOWSENTRY. Its purpose is to detect reconnaissance scans, automated bot probes, and unauthorized lateral movement attempts on monitored networks by simulating vulnerable network services.

Unlike full service deployments that present broad attack surfaces, SHADOWSENTRY honeypots are **lightweight, non-executable protocol simulations** engineered strictly for detection telemetry.

---

## 2. Simulated Honeypot Services

SHADOWSENTRY provides three initial decoy services:

| Service | Default Port | Protocol | Simulation Behavior |
| :--- | :---: | :---: | :--- |
| **HTTP Decoy** | `8080` | HTTP/1.1 | Responds to `GET` requests with a standard web server landing page ("Apache/2.4.52 (Ubuntu) Default Page"). Records HTTP methods, User-Agents, and probe paths. |
| **Admin Portal Simulator** | `8443` | HTTP/1.1 | Simulates an enterprise administrative login portal ("ShadowSentry Enterprise Gateway - Sign In"). Rejects all submitted credentials with "Authentication Failed", recording the probe attempt without saving passwords. |
| **SSH Banner Simulator** | `2222` | SSH-2.0 | Emulates an OpenSSH banner handshake (`SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4`). Immediately closes the socket upon receiving client banner/key exchange bytes. |

---

## 3. Containment & Safety Architecture

Because running listening network services introduces potential security risks, SHADOWSENTRY enforces strict defensive controls:

```
                            [ Client Connection ]
                                      │
                                      ▼
                        ┌───────────────────────────┐
                        │ Concurrent Limit Check    │  (Max 10 active connections)
                        │  (Exceeded -> Drop)       │
                        └─────────────┬─────────────┘
                                      │
                                      ▼
                        ┌───────────────────────────┐
                        │ Socket Timeout Guard      │  (Max 5.0 seconds total)
                        │  (Exceeded -> Close)      │
                        └─────────────┬─────────────┘
                                      │
                                      ▼
                        ┌───────────────────────────┐
                        │ Bounded Buffer Read       │  (Max 16 KB request body)
                        │  (Excess -> Truncated)    │
                        └─────────────┬─────────────┘
                                      │
                                      ▼
                        ┌───────────────────────────┐
                        │ Credential Dropping       │  (Cleartext passwords zeroized)
                        │  (Headers & Path Only)    │
                        └─────────────┬─────────────┘
                                      │
                                      ▼
                        ┌───────────────────────────┐
                        │ Forensic Logging (SQLite) │
                        │  + Heuristic Event Trigger│
                        └───────────────────────────┘
```

### 3.1. Loopback-by-Default Binding
- All honeypot services bind exclusively to `127.0.0.1` upon initial activation.
- At `127.0.0.1`, services are only accessible from the local host, allowing safe testing without exposing any listening ports to the physical LAN or Wi-Fi network.

### 3.2. Explicit LAN Exposure Confirmation
- If a security analyst explicitly selects `0.0.0.0` (Listen on All Network Interfaces):
  - SHADOWSENTRY displays a high-risk confirmation dialog explaining that listening ports will become reachable to all devices on the local subnet.
  - The user must explicitly type or confirm exposure before the service binds to `0.0.0.0`.

### 3.3. Zero Code Execution & Zero Shell Access
- Honeypot modules are implemented entirely in memory in Rust.
- They **do not execute `cmd.exe`, `powershell.exe`, or shell processes**.
- Client requests are parsed purely as text strings to extract HTTP headers or SSH banners.

### 3.4. Anti-Pivot Guarantee
- The honeypot sockets never initiate outbound connections.
- They cannot be configured as proxies, tunnels, or SOCKS endpoints. An attacker interacting with the honeypot cannot use SHADOWSENTRY to pivot into internal networks.

### 3.5. Credential Stripping
- While the Admin Portal simulation renders a mock login form to attract brute-force attempts, **it never stores credentials**. Submitted passwords are immediately zeroized in memory; only the metadata `interaction_type = "LOGIN_ATTEMPT"` and `source_ip` are persisted.

---

## 4. Windows Firewall & Network Reachability

1. **Loopback (`127.0.0.1`)**:
   - The Windows Defender Firewall automatically permits loopback socket communication. No firewall prompts will appear.
2. **Local Subnet (`0.0.0.0`)**:
   - When binding to `0.0.0.0`, the Windows Defender Firewall may display a security popup asking whether to allow `shadowsentry.exe` to accept incoming connections on Private/Public networks.
   - Users must explicitly grant this permission in the Windows Firewall dialog for LAN probes to reach the honeypot.
   - **SHADOWSENTRY never attempts to modify Windows Firewall rules silently**.

---

## 5. Threat Detection Integration

Every honeypot interaction generates an entry in the `honeypot_interactions` table. In addition:
- When repeated connections from a single IP address target honeypot ports within a short time window (e.g. >= 3 probes within 300 seconds), the Threat Detection Engine triggers `RULE_HONEYPOT_PROBE` with **High Severity**.
- The security event includes the exact timestamps, source IP, probed service, and recommended incident response actions.
