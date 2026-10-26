import subprocess
import time
import os
import sys

port = 8111
dist_dir = os.path.abspath("dist")
screenshots_dir = os.path.abspath(r"docs\assets\screenshots")
os.makedirs(screenshots_dir, exist_ok=True)

server = subprocess.Popen([sys.executable, "-m", "http.server", str(port), "--directory", dist_dir], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(2)

edge_path = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
if not os.path.exists(edge_path):
    edge_path = r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"

targets = [
    ("01_startup_splash.png", f"http://127.0.0.1:{port}"),
    ("02_main_dashboard.png", f"http://127.0.0.1:{port}/?skipIntro=true&tab=dashboard"),
    ("03_live_traffic.png", f"http://127.0.0.1:{port}/?skipIntro=true&tab=traffic"),
    ("04_threat_center.png", f"http://127.0.0.1:{port}/?skipIntro=true&tab=threats"),
    ("05_dns_intelligence.png", f"http://127.0.0.1:{port}/?skipIntro=true&tab=dns"),
    ("06_honeypot_lab.png", f"http://127.0.0.1:{port}/?skipIntro=true&tab=honeypot"),
    ("07_tutorial_guide.png", f"http://127.0.0.1:{port}/?skipIntro=true&tab=dashboard&tutorial=true"),
    ("08_event_history.png", f"http://127.0.0.1:{port}/?skipIntro=true&tab=events"),
    ("09_settings_privacy.png", f"http://127.0.0.1:{port}/?skipIntro=true&tab=settings"),
]

for filename, url in targets:
    out_file = os.path.join(screenshots_dir, filename)
    cmd = [
        edge_path,
        "--headless=new",
        "--disable-gpu",
        f"--screenshot={out_file}",
        "--window-size=1366,820",
        url
    ]
    try:
        subprocess.run(cmd, capture_output=True, timeout=12)
        exists = os.path.exists(out_file)
        size = os.path.getsize(out_file) if exists else 0
        print(f"Captured {filename}: {exists} ({size} bytes)")
    except Exception as e:
        print(f"Error capturing {filename}: {e}")

server.terminate()
print("All screenshot captures complete.")
