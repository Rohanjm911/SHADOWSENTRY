# Packet Capture Boundaries & Technical Limitations — SHADOWSENTRY

**SHADOWSENTRY: Invisible Threats. Visible Intelligence.**

---

## 1. Transparency in Cybersecurity

A core foundational principle of SHADOWSENTRY is **forensic honesty**. We reject marketing claims that promise "omnipresent 100% visibility" into all network threats. Physical network topology, transport encryption, and operating system permissions impose concrete technical boundaries.

---

## 2. Switched Network Architecture & L2 Isolation

### 2.1. The Switched Network Reality
In modern Ethernet networks (switches) and corporate Wi-Fi access points:
- Ethernet switches maintain MAC address tables (`CAM` tables) and forward unicast packets **strictly to the physical switch port connected to the destination MAC address**.
- Unicast traffic between Host B (e.g. 192.168.1.50) and Host C (e.g. 192.168.1.75) **does not physically pass through Host A's network interface**.
- Therefore, a workstation running SHADOWSENTRY cannot observe arbitrary unicast communication occurring between two external devices on the same LAN unless:
  1. A managed switch port mirroring (SPAN / RSPAN) session is configured to replicate traffic to the monitoring NIC.
  2. A physical network TAP is inserted inline.
  3. The traffic is Broadcast (e.g. ARP requests, NetBIOS) or Multicast (e.g. mDNS, SSDP), which switches forward to all ports in the broadcast domain.

### 2.2. Wi-Fi Client Isolation
On Wi-Fi networks configured with **Client Isolation** (common in hotels, guest networks, and enterprise SSIDs), the wireless access point drops direct station-to-station traffic at Layer 2. Station A cannot communicate with or observe Station B.

---

## 3. Encrypted Protocols & Application Layer Privacy

### 3.1. DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT)
- Traditional DNS queries traverse UDP or TCP port 53 in cleartext. SHADOWSENTRY detects, extracts, and analyzes these queries (including domain names and Shannon entropy).
- When a client browser or operating system enables **DNS-over-HTTPS (DoH)** (e.g. to Cloudflare `1.1.1.1` or Google `8.8.8.8` via TCP port 443) or **DNS-over-TLS (DoT)** (TCP port 853):
  - The query name and response are encrypted within TLS 1.3 tunnels.
  - SHADOWSENTRY observes the outer IP packet and port 443/853 metadata, but **cannot view the inner domain name or DNS records**.
  - SHADOWSENTRY clearly displays a notice explaining this privacy boundary.

### 3.2. TLS 1.3 Application Traffic
SHADOWSENTRY inspects network layer (IP) and transport layer (TCP/UDP) headers. Application layer content encrypted under TLS (HTTPS, SMTPS, IMAPS, SSH) is unreadable without installing local root CA certificates and performing active man-in-the-middle decryption—a practice SHADOWSENTRY deliberately avoids to maintain system stability and user privacy.

### 3.3. VPN & Encrypted Tunnels
When a system utilizes WireGuard, OpenVPN, or IPsec:
- Traffic leaving the physical network card consists of encrypted UDP/IPsec envelopes directed to the VPN gateway.
- SHADOWSENTRY monitors the physical adapter by default. To inspect pre-encrypted traffic, the virtual TUN/TAP adapter created by the VPN software must be explicitly selected as the capture interface.

---

## 4. Driver & Operating System Dependencies

| Capability | Npcap Driver Mode | Elevated Raw Sockets | Non-Elevated Mode |
| :--- | :---: | :---: | :---: |
| **Layer-2 Ethernet Frames** | Supported | Not Available | Simulation / Demo |
| **ARP Anomaly Detection** | Supported | IP Helper Table Only | Simulation / Demo |
| **IPv4 Packet Parsing** | Supported | Supported | Simulation / Demo |
| **IPv6 Packet Parsing** | Supported | Supported | Simulation / Demo |
| **TCP / UDP Metadata** | Supported | Supported | Simulation / Demo |
| **Cleartext DNS Inspection** | Supported | Supported | Simulation / Demo |
| **Promiscuous Mode** | Supported | Partial (SIO_RCVALL) | Not Available |
| **Admin Privilege Required** | Driver install only | Yes | No |

---

## 5. High-Throughput Buffering & Resource Limits

To prevent memory exhaustion during gigabit network saturation:
- SHADOWSENTRY implements a bounded ring buffer holding a maximum of **5,000 packets** (or ~64 MB).
- If traffic throughput exceeds processing rate, older unflagged packets are aged out gracefully.
- The UI displays packet drop and counter statistics so the user is always aware of capture fidelity.
