# Testing & Verification Guide — SHADOWSENTRY

**SHADOWSENTRY: Invisible Threats. Visible Intelligence.**

---

## 1. Testing Strategy & Philosophy

SHADOWSENTRY monitors live network traffic and triggers security alerts. Flawed parsing can crash the application, and flawed detection rules generate alert fatigue.

Our testing suite is structured into four decoupled layers:
1. **Rust Security Engine Tests (`src-tauri/src/bin/test_runner.rs`)**:
   - Zero-panic packet parser verification.
   - Shannon entropy math validation.
   - Deterministic rule triggering across all 10 detection rules.
   - SQLite CRUD, schema migrations, and sanitized export tests.
2. **Frontend Type & Production Build Tests**:
   - TypeScript strict compilation (`tsc`).
   - Vite bundling and asset tree verification (`vite build`).
3. **Fixture-Based Scenario Tests (`tests/`)**:
   - Synthetic packet fixtures in JSON format.
   - Detection case specifications with expected rule triggers.
   - Honeypot interaction scenarios.
4. **Traffic Generation Utility (`tools/generate_test_packets.py`)**:
   - Automated fixture generator producing synthetic packets for port scans, DGA DNS requests, gateway anomalies, and honeypot probes.

---

## 2. Running Automated Tests

### 2.1. Security Engine & Rule Verification (Rust)
Run the native security test runner from the repository root:
```powershell
cd src-tauri
cargo run --bin test_runner
```
**Expected Output**:
```
=== SHADOWSENTRY Native Security Test Suite ===
Running test: Packet Parser (Ethernet + IPv4 + TCP SYN)... [PASS]
Running test: Shannon Entropy Calculation... [PASS]
Running test: DNS Packet Parser & Query Extraction... [PASS]
Running test: Detection Rule: Port Scan Detection... [PASS]
Running test: Detection Rule: DNS DGA Anomaly Detection... [PASS]
Running test: Detection Rule: Gateway & ARP Conflict... [PASS]
Running test: Detection Rule: Threat Intel IP Matching... [PASS]
Running test: Honeypot Lab Heuristic Triggering... [PASS]
Running test: SQLite Database Persistence & Retention... [PASS]

=== Test Summary: 9 Passed, 0 Failed ===
```

### 2.2. Frontend Build Verification
Verify TypeScript types, JSX components, and Vite bundle generation:
```powershell
npm run build
```
This runs `tsc && vite build` and generates the production distribution in `dist/`.

---

## 3. Test Fixture Directory Structure

```
tests/
├── packet-fixtures/
│   ├── syn_scan_packet.json       # TCP SYN packet targeting port 80
│   ├── dga_dns_query.json         # High-entropy domain DNS query
│   └── arp_poison_packet.json     # Gratuitous ARP mapping conflict
├── detection-cases/
│   ├── rule_port_scan.json        # 25 rapid SYN packets to different ports
│   ├── rule_suspicious_dns.json   # Algorithmically generated domain query
│   ├── rule_gateway_change.json   # Gateway IP reassignment event
│   └── rule_threat_intel.json     # Traffic matching 198.51.100.23 indicator
└── honeypot-scenarios/
    ├── http_decoy_probe.json      # Inbound HTTP probe to port 8080
    ├── admin_portal_probe.json    # Inbound probe to port 8443
    └── ssh_banner_probe.json      # Inbound SSH probe to port 2222
```

---

## 4. Generating Synthetic Test Fixtures

To regenerate or customize test fixtures:
```powershell
python tools/generate_test_packets.py
```
This script populates `tests/packet-fixtures/`, `tests/detection-cases/`, and `tests/honeypot-scenarios/` with standard forensic payloads.

---

## 5. In-App Laboratory Demonstration Mode

For laboratory demonstration without live network activity or when capture drivers are unavailable:
1. Open SHADOWSENTRY.
2. Navigate to **Settings -> Laboratory Test Scenarios**.
3. Select any scenario:
   - **Inject Port Scan**: Emulates 25 rapid TCP SYN packets across ports 20-8080.
   - **Inject Suspicious DNS**: Emulates a high-entropy DNS query (`xj92k-secure-telemetry.biz`).
   - **Inject Gateway Anomaly**: Emulates an unexpected gateway MAC change (`00:11:22:33:44:55` -> `AA:BB:CC:DD:EE:FF`).
   - **Inject Honeypot Probe**: Emulates an inbound connection to the Admin Portal simulator.
4. Navigate to **Threat Center** or **Live Traffic** to observe the real-time detection, forensic evidence JSON, uncertainty analysis, and recommended response steps.
