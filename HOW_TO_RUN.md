# How to Run SHADOWSENTRY

### *Invisible Threats. Visible Intelligence. Native Windows Network Security Application.*

This guide provides end-to-end instructions for launching the pre-built standalone executable, selecting capture modes, compiling from source, and executing the automated security verification suite.

---

## 1. Quick Launch (Pre-Built Executable)

You do **not** need to install Node.js, Rust, or compilers to run the application. A standalone executable with embedded UI assets is pre-packaged in the project root directory.

### Launch Options

#### Option 1: Direct File Explorer Launch (Recommended)
1. Open the project root folder:
   ```
   d:\projects and certificates\projects\apps\Shadow Sentry\
   ```
2. Double-click [`ShadowSentry.exe`](file:///d:/projects%20and%20certificates/projects/apps/Shadow%20Sentry/ShadowSentry.exe).
3. Ensure [`WebView2Loader.dll`](file:///d:/projects%20and%20certificates/projects/apps/Shadow%20Sentry/WebView2Loader.dll) remains in the same folder.

#### Option 2: Run via npm Script
Open PowerShell or Command Prompt in the repository root and run:
```powershell
npm start
```

#### Option 3: Run via PowerShell Terminal
```powershell
cd "d:\projects and certificates\projects\apps\Shadow Sentry"
.\ShadowSentry.exe
```

---

## 2. Choosing Your Packet Capture Mode

SHADOWSENTRY supports three intelligent capture backends depending on your system privileges and installed drivers:

```
                          ┌───────────────────────────┐
                          │   SHADOWSENTRY Launcher   │
                          └─────────────┬─────────────┘
                                        │
             ┌──────────────────────────┼──────────────────────────┐
             ▼                          ▼                          ▼
   [Npcap Driver Found]       [Admin Token Present]       [Standard Non-Admin]
             │                          │                          │
             ▼                          ▼                          ▼
   Mode 1: Npcap Driver       Mode 2: Windows Raw Socket   Mode 3: Lab Synthetic Mode
  (Promiscuous Layer-2/3)        (Native IP/TCP/UDP)        (Safe Offline Simulation)
```

### Mode 1: Windows Native Raw Sockets (100% Real Live Packets, Zero Drivers)
- **Privilege Required:** Administrator
- **Capabilities:** Captures live IPv4 packets, TCP SYN/ACK/RST flags, UDP datagrams, and DNS queries directly from Windows network interfaces without installing third-party drivers.
- **How to Launch:**
  1. Right-click [`ShadowSentry.exe`](file:///d:/projects%20and%20certificates/projects/apps/Shadow%20Sentry/ShadowSentry.exe).
  2. Select **"Run as administrator"**.
  3. Click **"Yes"** on the Windows UAC elevation prompt.

### Mode 2: Npcap Driver Mode (Promiscuous Layer-2 Ethernet)
- **Privilege Required:** Standard or Administrator (with Npcap service active)
- **Capabilities:** Captures raw Ethernet frames, ARP poisoning anomalies, and all promiscuous subnet traffic.
- **How to Enable:**
  1. Download and install [Npcap](https://npcap.com/#download).
  2. During installation, ensure the checkbox **"Install Npcap in WinPcap API-compatible Mode"** is checked.
  3. Launch [`ShadowSentry.exe`](file:///d:/projects%20and%20certificates/projects/apps/Shadow%20Sentry/ShadowSentry.exe). The application dynamically detects `wpcap.dll` and begins Layer-2 capture.

### Mode 3: Lab Synthetic Mode (Safe Offline Simulation)
- **Privilege Required:** Standard Non-Admin User (Zero Elevation)
- **Capabilities:** If launched without Administrator rights and without Npcap, SHADOWSENTRY safely starts in **Lab Simulation Mode**.
- Generates realistic synthetic traffic, DNS queries, port scans, and gateway transitions to allow complete evaluation of the UI, detection rules, and investigation workflows without permission errors.

---

## 3. Running in Development Mode

If you want to modify the source code with hot-reloading:

### 1. Install Dependencies
```powershell
npm install
```

### 2. Start Frontend Dev Server
```powershell
npm run dev
```
Starts Vite at `http://localhost:1420`.

### 3. Launch Tauri Dev Window
In a second terminal window:
```powershell
npx tauri dev
```

---

## 4. Building from Source

To compile a fresh standalone binary or a Windows `.msi` installer:

### Step 1: Build Frontend Production Assets
```powershell
npm run build
```
Generates optimized static web assets inside `./dist`.

### Step 2: Compile Rust Desktop Application
```powershell
cargo build --manifest-path src-tauri/Cargo.toml
```
Outputs the native binary to:
```
./src-tauri/target/debug/shadowsentry.exe
```

### Step 3: Copy Standalone Binary to Root
```powershell
Copy-Item "src-tauri/target/debug/shadowsentry.exe" "ShadowSentry.exe" -Force
```

### Step 4: Package Windows MSI Installer (Optional)
```powershell
npx tauri build --debug --no-sign --bundles msi
```
Outputs the MSI installer to:
```
./src-tauri/target/debug/bundle/msi/ShadowSentry_0.1.0_x64_en-US.msi
```

---

## 5. Running Security Tests & Honeypot Probes

### 1. Run Automated Rust Verification Suite (14 Tests)
Validates frame parsers, Shannon entropy mathematics, all 10 explainable detection rules, and SQLite CRUD:
```powershell
cd src-tauri
cargo run --bin test_runner
cd ..
```
*Expected Result:* `14 passed; 0 failed`.

### 2. Generate Test Scenario Fixtures
Regenerates all 10 detection case JSON fixtures and honeypot scenarios:
```powershell
python tools/generate_test_packets.py
```

### 3. Send Probe to Local Honeypot HTTP Decoy (Port 8080)
```powershell
python tools/generate_test_packets.py --test-http
```
*Sends test reconnaissance probes for `/.env`, `/admin`, and `/wp-login.php` to verify Rule 8 detection.*

### 4. Send Probe to Local Honeypot SSH Simulator (Port 2222)
```powershell
python tools/generate_test_packets.py --test-ssh
```
*Sends client SSH protocol handshakes to verify banner capture and socket termination.*

---

## 6. Desktop Navigation & Shortcuts

| Shortcut | Action | Description |
| :---: | :--- | :--- |
| `Ctrl + 1` | **Dashboard** | Overview cards, bandwidth rate, detection timeline. |
| `Ctrl + 2` | **Live Traffic** | High-throughput streaming packet inspector table. |
| `Ctrl + 3` | **Alerts** | Explainable security detections with evidence panels. |
| `Ctrl + 4` | **DNS Monitor** | Domain queries, record types, and Shannon entropy analysis. |
| `Ctrl + 5` | **Honeypot Lab** | Opt-in decoy services (HTTP :8080, Admin :8088, SSH :2222). |
| `Ctrl + 6` | **Discovery** | Win32 ARP table, host inventory, and gateway MAC state. |
| `Ctrl + 7` | **Forensics** | Multi-attribute search, CSV/JSON export, and data purge. |
| `Ctrl + 8` | **Settings** | Thresholds, retention ceilings, dark theme switcher. |
| `Escape` | **Close Overlays** | Closes active investigation panels, modal drawers, and popups. |

---

## 7. Troubleshooting

| Issue | Cause | Solution |
| :--- | :--- | :--- |
| **"localhost refused to connect"** | Binary was pointing to a dev server rather than embedded assets. | Replaced by the standalone binary in root which embeds `../dist` directly. |
| **`Access is denied` on Raw Sockets** | Windows prevents non-administrators from binding `SOCK_RAW`. | Right-click `ShadowSentry.exe` and select **"Run as administrator"**, or allow it to fall back to **Lab Synthetic Mode**. |
| **Windows Defender Antivirus Warning** | Unsigned local developer binary. | Click **"More info"** ➔ **"Run anyway"**. SHADOWSENTRY is 100% open-source and has zero telemetry. |
| **Port Conflict on Honeypot (8080/8088/2222)** | Another local service (e.g. Apache, Docker, or OpenSSH) is using the port. | Open the **Honeypot Lab** tab (`Ctrl+5`), edit the port configuration input, and click **Save**. |
