import subprocess
import os
import json
import time
import random
from datetime import datetime, UTC

LOG_FILE = "scanner_log.json"

def log_event(event_type, message, data=None):
    event = {
        "time": datetime.now(UTC).isoformat(),
        "type": event_type,
        "message": message,
        "data": data or {}
    }
    try:
        with open("events.json", "r") as f:
            events = json.load(f)
    except FileNotFoundError:
        events = []
    events.append(event)
    events = events[-200:]
    with open("events.json", "w") as f:
        json.dump(events, f, indent=2)

def load_scanner_log():
    try:
        with open(LOG_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        return {"running": False, "scans": 0, "threats_found": 0, "last_scan": None}

def save_scanner_log(data):
    with open(LOG_FILE, "w") as f:
        json.dump(data, f, indent=2)

def is_scanner_enabled():
    """Check if scanner toggle is on"""
    try:
        with open("scanner_state.json") as f:
            state = json.load(f)
        return state.get("enabled", False)
    except FileNotFoundError:
        return False

def run_scan():
    """
    Run one scan cycle.
    65% chance of finding a threat and running the full pipeline.
    35% chance of finding nothing.
    """
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    scanner_data = load_scanner_log()
    scanner_data["scans"] += 1
    scanner_data["last_scan"] = datetime.now(UTC).isoformat()

    # Randomly pick which feed to scan
    feeds = [
        "OSINT Feed",
        "CVE Database",
        "Dark Web Intel",
        "Honeypot Network",
        "Threat Intel Share",
        "EDR Telemetry",
        "DNS Monitor",
        "Email Security Feed"
    ]
    feed = random.choice(feeds)

    log_event("scanner", f"[AUTO-SCAN #{scanner_data['scans']}] Scanning {feed}...")

    # 65% chance of finding a threat
    found_threat = random.random() < 0.65

    if found_threat:
        log_event("scanner", f"[AUTO-SCAN] Potential threat signal detected in {feed}. Initiating pipeline...")

        # Set to push mode
        with open("pipeline_mode.json", "w") as f:
            json.dump({"mode": "push"}, f)

        # Run full push pipeline
        for agent in ["sensor", "enrichment", "verification"]:
            result = subprocess.run(
                ["python", f"agents/{agent}_agent.py"],
                capture_output=True,
                text=True,
                env=env
            )
            if result.returncode != 0:
                log_event("scanner", f"[AUTO-SCAN] Error in {agent} agent. Aborting scan.")
                save_scanner_log(scanner_data)
                return

        result = subprocess.run(
            ["python", "agents/consumer_agent.py", "push"],
            capture_output=True,
            text=True,
            env=env
        )

        scanner_data["threats_found"] += 1
        log_event("scanner", f"[AUTO-SCAN #{scanner_data['scans']}] Pipeline complete. Threats found so far: {scanner_data['threats_found']}")

    else:
        log_event("scanner", f"[AUTO-SCAN #{scanner_data['scans']}] Scan complete. No actionable threats found in {feed}.")

    save_scanner_log(scanner_data)

def run_scanner():
    """
    Main scanner loop.
    Checks every 10 seconds if scanner is enabled.
    When enabled, runs a scan every 2-4 minutes.
    """
    print("[SCANNER] ThreatMesh auto-scanner started.")
    print("[SCANNER] Waiting for toggle to be enabled via dashboard...")

    # Track when the last scan ran
    last_scan_time = 0

    # Randomize scan interval between 2 and 4 minutes
    scan_interval = random.randint(120, 240)

    while True:
        try:
            enabled = is_scanner_enabled()

            if enabled:
                now = time.time()
                time_since_last = now - last_scan_time

                if time_since_last >= scan_interval:
                    print(f"[SCANNER] Running auto-scan (interval: {scan_interval}s)...")
                    run_scan()
                    last_scan_time = time.time()
                    # Randomize next interval
                    scan_interval = random.randint(120, 240)
                    print(f"[SCANNER] Next scan in {scan_interval} seconds.")
                else:
                    remaining = int(scan_interval - time_since_last)
                    if remaining % 30 == 0:
                        print(f"[SCANNER] Next scan in {remaining}s...")
            else:
                # Reset timer when disabled so it scans soon after re-enabling
                last_scan_time = 0
                scan_interval = random.randint(120, 240)

        except Exception as e:
            print(f"[SCANNER] Error: {e}")

        time.sleep(10)

if __name__ == "__main__":
    run_scanner()