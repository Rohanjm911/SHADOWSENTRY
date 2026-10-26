#!/usr/bin/env python3
"""
SHADOWSENTRY — Test Packet Generator & Security Laboratory Utility
"Invisible Threats. Visible Intelligence."

Generates test packet fixtures and provides controlled laboratory probe injection
to verify detection rules and honeypot services.
"""

import os
import sys
import json
import time
import socket
import argparse
import urllib.request
import urllib.error

def generate_fixtures(output_dir="tests"):
    os.makedirs(os.path.join(output_dir, "packet-fixtures"), exist_ok=True)
    os.makedirs(os.path.join(output_dir, "detection-cases"), exist_ok=True)
    os.makedirs(os.path.join(output_dir, "honeypot-scenarios"), exist_ok=True)

    # 1. Port scan test case fixture (Rule 1)
    port_scan_case = {
        "rule_id": "RULE-01-PORT-SCAN",
        "description": "20 consecutive TCP SYN packets across multiple ports from single source",
        "source_ip": "192.168.1.188",
        "target_ip": "192.168.1.145",
        "target_ports": list(range(1000, 1020)),
        "protocol": "TCP",
        "tcp_flags": {"syn": True, "ack": False},
        "expected_severity": "high",
        "expected_rule": "RULE-01-PORT-SCAN"
    }
    with open(os.path.join(output_dir, "detection-cases", "case_01_port_scan.json"), "w") as f:
        json.dump(port_scan_case, f, indent=2)

    # 2. Connection burst fixture (Rule 2)
    burst_case = {
        "rule_id": "RULE-02-BURST",
        "description": "Sudden surge of 1500 packets within 5 seconds",
        "packet_rate": 300,
        "window_seconds": 5,
        "protocol": "TCP",
        "expected_severity": "medium"
    }
    with open(os.path.join(output_dir, "detection-cases", "case_02_connection_burst.json"), "w") as f:
        json.dump(burst_case, f, indent=2)

    # 3. Connection failures / RST surge fixture (Rule 3)
    conn_failures_case = {
        "rule_id": "RULE-03-CONN-FAILURES",
        "description": "Repeated TCP RST packets indicating rejected connection attempts",
        "source_ip": "192.168.1.55",
        "target_ip": "192.168.1.10",
        "rst_count": 25,
        "window_seconds": 10,
        "expected_severity": "medium"
    }
    with open(os.path.join(output_dir, "detection-cases", "case_03_connection_failures.json"), "w") as f:
        json.dump(conn_failures_case, f, indent=2)

    # 4. DGA Suspicious DNS test case fixture (Rule 4)
    dga_case = {
        "rule_id": "RULE-04-SUSP-DNS",
        "description": "Algorithmically generated high-entropy domain name query",
        "domain": "x87ab29c4f091bc883adq01.malicious-domain-dga.top",
        "record_type": "A",
        "entropy_score": 4.12,
        "length": 48,
        "expected_severity": "high"
    }
    with open(os.path.join(output_dir, "detection-cases", "case_04_dga_dns.json"), "w") as f:
        json.dump(dga_case, f, indent=2)

    # 5. Gateway change fixture (Rule 5)
    gw_case = {
        "rule_id": "RULE-05-GATEWAY-CHANGE",
        "description": "Default gateway MAC address changed unexpectedly",
        "gateway_ip": "192.168.1.1",
        "previous_mac": "70:4F:57:A2:BB:01",
        "new_mac": "AA:BB:CC:DD:EE:FF",
        "expected_severity": "high"
    }
    with open(os.path.join(output_dir, "detection-cases", "case_05_gateway_change.json"), "w") as f:
        json.dump(gw_case, f, indent=2)

    # 6. ARP Anomaly test case fixture (Rule 6)
    arp_case = {
        "rule_id": "RULE-06-ARP-ANOMALY",
        "description": "Gateway IP 192.168.1.1 mapped to conflicting secondary MAC",
        "target_ip": "192.168.1.1",
        "legitimate_mac": "70:4F:57:A2:BB:01",
        "conflicting_mac": "00:11:22:33:44:99",
        "opcode": 2, # Reply
        "expected_severity": "critical"
    }
    with open(os.path.join(output_dir, "detection-cases", "case_06_arp_anomaly.json"), "w") as f:
        json.dump(arp_case, f, indent=2)

    # 7. Threat Intel match fixture (Rule 7)
    threat_intel_case = {
        "rule_id": "RULE-07-THREAT-INTEL",
        "description": "Outbound connection to known malicious C2 IP address",
        "matched_ip": "185.220.101.5",
        "protocol": "TCP",
        "dest_port": 443,
        "expected_severity": "critical"
    }
    with open(os.path.join(output_dir, "detection-cases", "case_07_threat_intel.json"), "w") as f:
        json.dump(threat_intel_case, f, indent=2)

    # 8. Honeypot interaction fixture (Rule 8)
    honeypot_hit_case = {
        "rule_id": "RULE-08-HONEYPOT-INTERACTION",
        "description": "Repeated probe against local decoy service",
        "service": "HttpDecoy",
        "client_ip": "192.168.1.200",
        "target_path": "/.env",
        "expected_severity": "critical"
    }
    with open(os.path.join(output_dir, "detection-cases", "case_08_honeypot_interaction.json"), "w") as f:
        json.dump(honeypot_hit_case, f, indent=2)

    # 9. Inbound anomaly fixture (Rule 9)
    inbound_case = {
        "rule_id": "RULE-09-INBOUND-ANOMALY",
        "description": "Unsolicited inbound TCP SYN connection targeting sensitive port 445 (SMB)",
        "source_ip": "10.10.10.200",
        "dest_port": 445,
        "protocol": "TCP",
        "tcp_flags": {"syn": True, "ack": False},
        "expected_severity": "high"
    }
    with open(os.path.join(output_dir, "detection-cases", "case_09_inbound_anomaly.json"), "w") as f:
        json.dump(inbound_case, f, indent=2)

    # 10. Config change fixture (Rule 10)
    config_case = {
        "rule_id": "RULE-10-CONFIG-CHANGE",
        "description": "Monitoring network interface disconnected during active session",
        "event_summary": "Primary network adapter transitioned to Down state",
        "expected_severity": "medium"
    }
    with open(os.path.join(output_dir, "detection-cases", "case_10_config_change.json"), "w") as f:
        json.dump(config_case, f, indent=2)

    # Honeypot Scenarios
    with open(os.path.join(output_dir, "honeypot-scenarios", "scenario_http_decoy.json"), "w") as f:
        json.dump({
            "service": "http_decoy",
            "probes": [
                {"method": "GET", "path": "/.env", "expected_code": 403},
                {"method": "GET", "path": "/admin", "expected_code": 403},
                {"method": "GET", "path": "/robots.txt", "expected_code": 200},
                {"method": "POST", "path": "/api/v1/auth", "expected_code": 403}
            ]
        }, f, indent=2)

    with open(os.path.join(output_dir, "honeypot-scenarios", "scenario_admin_panel.json"), "w") as f:
        json.dump({
            "service": "admin_panel",
            "probes": [
                {"method": "GET", "path": "/login", "expected_code": 200},
                {"method": "POST", "path": "/login", "expected_code": 401},
                {"method": "GET", "path": "/dashboard", "expected_code": 302}
            ]
        }, f, indent=2)

    with open(os.path.join(output_dir, "honeypot-scenarios", "scenario_ssh_banner.json"), "w") as f:
        json.dump({
            "service": "ssh_banner",
            "banner_expected": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
            "probe_action": "connect_and_read_banner"
        }, f, indent=2)

    # Packet Fixtures
    with open(os.path.join(output_dir, "packet-fixtures", "tcp_syn_probe.json"), "w") as f:
        json.dump({
            "protocol": "TCP",
            "src_ip": "192.168.1.188",
            "dest_ip": "192.168.1.145",
            "src_port": 54321,
            "dest_port": 80,
            "flags": {"syn": True, "ack": False},
            "length": 60
        }, f, indent=2)

    with open(os.path.join(output_dir, "packet-fixtures", "dns_query_wire.json"), "w") as f:
        json.dump({
            "protocol": "DNS",
            "query_name": "google.com",
            "query_type": "A",
            "id": 4660,
            "wire_hex": "12340100000100000000000006676f6f676c6503636f6d0000010001"
        }, f, indent=2)

    with open(os.path.join(output_dir, "packet-fixtures", "arp_conflict_frame.json"), "w") as f:
        json.dump({
            "protocol": "ARP",
            "sender_ip": "192.168.1.1",
            "sender_mac": "00:11:22:33:44:99",
            "target_ip": "192.168.1.145",
            "opcode": 2
        }, f, indent=2)

    with open(os.path.join(output_dir, "packet-fixtures", "malformed_ip_frame.json"), "w") as f:
        json.dump({
            "protocol": "CORRUPT",
            "raw_hex": "ffffffffffff0000000000000800450000140000",
            "expected_behavior": "safe_discard_no_panic"
        }, f, indent=2)

    print(f"Generated test fixtures in '{output_dir}/'")

def test_honeypot_http(host="127.0.0.1", port=8080):
    url = f"http://{host}:{port}/.env"
    print(f"Sending test recon probe to HTTP Decoy: {url}")
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "SHADOWSENTRY-LabTest/1.0 (Authorized Security Audit)"}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            print(f"Response status: {resp.status}")
            print(f"Body: {resp.read()[:100]}")
    except urllib.error.HTTPError as e:
        print(f"HTTP response code: {e.code} (Honeypot successfully intercepted probe)")
    except Exception as e:
        print(f"Connection failed: {e}. (Ensure Honeypot HTTP Decoy is started on {host}:{port})")

def test_honeypot_ssh(host="127.0.0.1", port=2222):
    print(f"Connecting to SSH Banner Simulator at {host}:{port}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((host, port))
        banner = s.recv(1024)
        print(f"Received Honeypot Banner: {banner.decode(errors='ignore').strip()}")
        client_banner = b"SSH-2.0-LabTestClient_1.0\r\n"
        s.sendall(client_banner)
        time.sleep(0.5)
        s.close()
        print("SSH version handshake probe completed successfully.")
    except Exception as e:
        print(f"SSH probe failed: {e}. (Ensure Honeypot SSH service is started on {host}:{port})")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SHADOWSENTRY Test Packet & Lab Probe Generator")
    parser.add_argument("--generate-fixtures", action="store_true", help="Generate JSON test case fixtures")
    parser.add_argument("--test-http", action="store_true", help="Send test probe to HTTP decoy honeypot")
    parser.add_argument("--test-ssh", action="store_true", help="Send test probe to SSH banner honeypot")
    parser.add_argument("--port", type=int, default=0, help="Override target port")

    args = parser.parse_args()

    if args.generate_fixtures or len(sys.argv) == 1:
        generate_fixtures()

    if args.test_http:
        p = args.port if args.port > 0 else 8080
        test_honeypot_http(port=p)

    if args.test_ssh:
        p = args.port if args.port > 0 else 2222
        test_honeypot_ssh(port=p)
