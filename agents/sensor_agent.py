import requests
import json
import uuid
import os
import random
from datetime import datetime, UTC
from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import base64

load_dotenv()

API_KEY = os.getenv("CIRCLE_API_KEY")
ENTITY_SECRET = os.getenv("ENTITY_SECRET")
BASE_URL = "https://api.circle.com/v1/w3s"

HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

SEVERITY_PRICING = {
    "low":      0.005,
    "medium":   0.008,
    "high":     0.012,
    "critical": 0.018
}

SENSOR_REVENUE_SHARE = 0.50

# 50+ threats across multiple categories
THREAT_LIBRARY = [

    # --- RECONNAISSANCE ---
    {"type": "port_scan", "source_ip": "192.168.{}.{}", "port": 22, "severity": "medium",
     "region": "Eastern Europe", "feed": "Honeypot Alert"},
    {"type": "network_sweep", "source_ip": "45.142.{}.{}", "port": 0, "severity": "low",
     "region": "Russia", "feed": "OSINT Feed"},
    {"type": "dns_enumeration", "source_ip": "91.108.{}.{}", "port": 53, "severity": "medium",
     "region": "China", "feed": "Dark Web Intel"},
    {"type": "subdomain_harvest", "source_ip": "185.220.{}.{}", "port": 443, "severity": "low",
     "region": "Iran", "feed": "OSINT Feed"},
    {"type": "ssl_cert_recon", "source_ip": "194.165.{}.{}", "port": 443, "severity": "low",
     "region": "Russia", "feed": "CVE Database"},

    # --- CREDENTIAL ATTACKS ---
    {"type": "brute_force_ssh", "source_ip": "10.0.{}.{}", "port": 22, "severity": "high",
     "region": "North Korea", "feed": "Honeypot Alert"},
    {"type": "brute_force_rdp", "source_ip": "37.120.{}.{}", "port": 3389, "severity": "high",
     "region": "Russia", "feed": "Threat Intel Share"},
    {"type": "credential_stuffing", "source_ip": "198.51.{}.{}", "port": 443, "severity": "high",
     "region": "China", "feed": "Dark Web Intel"},
    {"type": "password_spray", "source_ip": "5.188.{}.{}", "port": 80, "severity": "medium",
     "region": "Eastern Europe", "feed": "SIEM Correlation"},
    {"type": "kerberoasting", "source_ip": "172.16.{}.{}", "port": 88, "severity": "critical",
     "region": "Internal", "feed": "EDR Alert"},

    # --- WEB APPLICATION ATTACKS ---
    {"type": "sql_injection", "source_ip": "172.16.{}.{}", "port": 80, "severity": "critical",
     "region": "China", "feed": "WAF Alert"},
    {"type": "xss_injection", "source_ip": "103.224.{}.{}", "port": 443, "severity": "medium",
     "region": "Southeast Asia", "feed": "WAF Alert"},
    {"type": "command_injection", "source_ip": "45.33.{}.{}", "port": 8080, "severity": "critical",
     "region": "Russia", "feed": "WAF Alert"},
    {"type": "path_traversal", "source_ip": "89.248.{}.{}", "port": 80, "severity": "high",
     "region": "Eastern Europe", "feed": "WAF Alert"},
    {"type": "ssrf_exploit", "source_ip": "107.189.{}.{}", "port": 443, "severity": "critical",
     "region": "China", "feed": "CVE Database"},
    {"type": "log4shell_probe", "source_ip": "45.142.{}.{}", "port": 443, "severity": "critical",
     "region": "Russia", "feed": "CVE Database", "cve": "CVE-2021-44228"},
    {"type": "spring4shell_probe", "source_ip": "194.165.{}.{}", "port": 8080, "severity": "critical",
     "region": "China", "feed": "CVE Database", "cve": "CVE-2022-22965"},

    # --- MALWARE & C2 ---
    {"type": "malware_beacon", "source_ip": "198.51.{}.{}", "port": 8080, "severity": "critical",
     "region": "North Korea", "feed": "EDR Alert"},
    {"type": "ransomware_c2", "source_ip": "91.108.{}.{}", "port": 4444, "severity": "critical",
     "region": "Russia", "feed": "Dark Web Intel"},
    {"type": "botnet_checkin", "source_ip": "185.220.{}.{}", "port": 443, "severity": "high",
     "region": "Eastern Europe", "feed": "Threat Intel Share"},
    {"type": "trojan_dropper", "source_ip": "77.247.{}.{}", "port": 80, "severity": "critical",
     "region": "Russia", "feed": "EDR Alert"},
    {"type": "rootkit_install", "source_ip": "185.100.{}.{}", "port": 0, "severity": "critical",
     "region": "China", "feed": "EDR Alert"},
    {"type": "keylogger_exfil", "source_ip": "94.102.{}.{}", "port": 443, "severity": "critical",
     "region": "Iran", "feed": "EDR Alert"},
    {"type": "cryptominer_deploy", "source_ip": "45.95.{}.{}", "port": 3333, "severity": "medium",
     "region": "Eastern Europe", "feed": "SIEM Correlation"},

    # --- DATA EXFILTRATION ---
    {"type": "data_exfil_ftp", "source_ip": "45.33.{}.{}", "port": 21, "severity": "high",
     "region": "China", "feed": "DLP Alert"},
    {"type": "data_exfil_dns", "source_ip": "203.0.{}.{}", "port": 53, "severity": "critical",
     "region": "North Korea", "feed": "DNS Monitor"},
    {"type": "data_exfil_https", "source_ip": "185.220.{}.{}", "port": 443, "severity": "critical",
     "region": "Russia", "feed": "DLP Alert"},
    {"type": "db_dump_attempt", "source_ip": "91.108.{}.{}", "port": 3306, "severity": "critical",
     "region": "China", "feed": "Database Monitor"},
    {"type": "cloud_storage_leak", "source_ip": "52.91.{}.{}", "port": 443, "severity": "high",
     "region": "United States", "feed": "Cloud Monitor"},

    # --- NETWORK ATTACKS ---
    {"type": "ddos_udp_flood", "source_ip": "203.0.{}.{}", "port": 443, "severity": "high",
     "region": "Russia", "feed": "Network Monitor"},
    {"type": "ddos_http_flood", "source_ip": "185.176.{}.{}", "port": 80, "severity": "high",
     "region": "China", "feed": "Network Monitor"},
    {"type": "syn_flood", "source_ip": "45.142.{}.{}", "port": 443, "severity": "high",
     "region": "Eastern Europe", "feed": "Firewall Alert"},
    {"type": "arp_spoofing", "source_ip": "10.0.{}.{}", "port": 0, "severity": "medium",
     "region": "Internal", "feed": "Network Monitor"},
    {"type": "mitm_attack", "source_ip": "172.16.{}.{}", "port": 443, "severity": "critical",
     "region": "Internal", "feed": "Network Monitor"},

    # --- APT CAMPAIGNS ---
    {"type": "apt_lateral_move", "source_ip": "172.16.{}.{}", "port": 445, "severity": "critical",
     "region": "Russia", "feed": "Threat Intel Share", "actor": "APT-29"},
    {"type": "apt_persistence", "source_ip": "10.0.{}.{}", "port": 0, "severity": "critical",
     "region": "China", "feed": "EDR Alert", "actor": "APT-41"},
    {"type": "apt_spearphish", "source_ip": "194.165.{}.{}", "port": 25, "severity": "high",
     "region": "North Korea", "feed": "Email Security", "actor": "Lazarus"},
    {"type": "supply_chain_inject", "source_ip": "52.84.{}.{}", "port": 443, "severity": "critical",
     "region": "Russia", "feed": "Dark Web Intel", "actor": "APT-29"},
    {"type": "watering_hole", "source_ip": "185.220.{}.{}", "port": 80, "severity": "high",
     "region": "Iran", "feed": "Threat Intel Share", "actor": "APT-33"},

    # --- CLOUD & SAAS ATTACKS ---
    {"type": "cloud_iam_abuse", "source_ip": "52.91.{}.{}", "port": 443, "severity": "critical",
     "region": "Eastern Europe", "feed": "Cloud Monitor"},
    {"type": "s3_bucket_expose", "source_ip": "54.239.{}.{}", "port": 443, "severity": "high",
     "region": "United States", "feed": "Cloud Monitor"},
    {"type": "api_key_leak", "source_ip": "140.82.{}.{}", "port": 443, "severity": "high",
     "region": "United States", "feed": "Dark Web Intel"},
    {"type": "oauth_token_theft", "source_ip": "185.199.{}.{}", "port": 443, "severity": "critical",
     "region": "Russia", "feed": "Cloud Monitor"},
    {"type": "container_escape", "source_ip": "10.0.{}.{}", "port": 2375, "severity": "critical",
     "region": "Internal", "feed": "Container Monitor"},

    # --- INSIDER THREATS ---
    {"type": "insider_data_theft", "source_ip": "10.0.{}.{}", "port": 443, "severity": "critical",
     "region": "Internal", "feed": "DLP Alert"},
    {"type": "privilege_escalation", "source_ip": "172.16.{}.{}", "port": 0, "severity": "critical",
     "region": "Internal", "feed": "EDR Alert"},
    {"type": "policy_violation", "source_ip": "192.168.{}.{}", "port": 80, "severity": "medium",
     "region": "Internal", "feed": "SIEM Correlation"},
    {"type": "after_hours_access", "source_ip": "10.10.{}.{}", "port": 22, "severity": "medium",
     "region": "Internal", "feed": "SIEM Correlation"},

    # --- ZERO DAYS ---
    {"type": "zero_day_browser", "source_ip": "185.220.{}.{}", "port": 443, "severity": "critical",
     "region": "Russia", "feed": "Dark Web Intel"},
    {"type": "zero_day_kernel", "source_ip": "94.102.{}.{}", "port": 0, "severity": "critical",
     "region": "China", "feed": "Dark Web Intel"},
    {"type": "zero_day_vpn", "source_ip": "45.142.{}.{}", "port": 1194, "severity": "critical",
     "region": "North Korea", "feed": "CVE Database"},

    # --- PHISHING ---
    {"type": "phishing_kit", "source_ip": "185.220.{}.{}", "port": 443, "severity": "medium",
     "region": "Eastern Europe", "feed": "Email Security"},
    {"type": "spear_phishing", "source_ip": "194.165.{}.{}", "port": 25, "severity": "high",
     "region": "Iran", "feed": "Email Security"},
    {"type": "vishing_campaign", "source_ip": "91.108.{}.{}", "port": 5060, "severity": "medium",
     "region": "Eastern Europe", "feed": "Threat Intel Share"},
]

# Region to geo coordinates mapping for the world map
REGION_COORDS = {
    "Russia":         {"lat": 55.75, "lng": 37.62},
    "China":          {"lat": 39.90, "lng": 116.40},
    "North Korea":    {"lat": 39.03, "lng": 125.75},
    "Iran":           {"lat": 35.69, "lng": 51.42},
    "Eastern Europe": {"lat": 50.45, "lng": 30.52},
    "Southeast Asia": {"lat": 13.75, "lng": 100.52},
    "United States":  {"lat": 37.77, "lng": -122.43},
    "Internal":       {"lat": 51.50, "lng": -0.12},
}

def get_entity_secret_ciphertext():
    res = requests.get(f"{BASE_URL}/config/entity/publicKey", headers=HEADERS)
    public_key_pem = res.json()["data"]["publicKey"]
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    encrypted = public_key.encrypt(
        bytes.fromhex(ENTITY_SECRET),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

def generate_threat():
    template = random.choice(THREAT_LIBRARY).copy()
    template["source_ip"] = template["source_ip"].format(
        random.randint(1, 254), random.randint(1, 254)
    )
    template["timestamp"] = datetime.now(UTC).isoformat()
    template["threat_id"] = str(uuid.uuid4())[:8]
    template["sale_price"] = SEVERITY_PRICING[template["severity"]]
    template["sensor_cut"] = round(template["sale_price"] * SENSOR_REVENUE_SHARE, 6)

    region = template.get("region", "Unknown")
    coords = REGION_COORDS.get(region, {"lat": 0, "lng": 0})
    coords["lat"] += random.uniform(-3, 3)
    coords["lng"] += random.uniform(-3, 3)
    template["geo"] = {"region": region, "lat": round(coords["lat"], 2), "lng": round(coords["lng"], 2)}

    return template

def send_payment(from_wallet_id, to_address, amount):
    ciphertext = get_entity_secret_ciphertext()
    body = {
        "idempotencyKey": str(uuid.uuid4()),
        "entitySecretCiphertext": ciphertext,
        "amounts": [str(amount)],
        "destinationAddress": to_address,
        "feeLevel": "MEDIUM",
        "blockchain": "ARC-TESTNET",
        "walletId": from_wallet_id,
        "tokenAddress": "0x3600000000000000000000000000000000000000"
    }
    res = requests.post(
        f"{BASE_URL}/developer/transactions/transfer",
        json=body,
        headers=HEADERS
    )
    return res.json()

def log_event(event_type, message, data=None):
    """Write a live event to the event stream file"""
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

def check_for_threats():
    # 65% chance of finding a threat during a scan
    if random.random() > 0.35:
        return generate_threat()
    return None

def run_push_mode(wallets):
    print("[SENSOR - PUSH MODE] Scanning network for threats...")
    log_event("sensor", "Scanning threat feeds: OSINT, CVE Database, Dark Web Intel, Honeypots...")

    threat = generate_threat()
    feed = threat.get("feed", "Unknown Feed")
    cve = threat.get("cve", "")
    cve_str = f" ({cve})" if cve else ""

    print(f"[SENSOR] Threat detected: {threat['type']} from {threat['source_ip']}")
    print(f"[SENSOR] Severity: {threat['severity'].upper()} | Feed: {feed} | Region: {threat['geo']['region']}")
    log_event("sensor", f"THREAT DETECTED via {feed}{cve_str}: {threat['type'].replace('_',' ').upper()} from {threat['geo']['region']}", threat)

    print(f"[SENSOR] Sale price: ${threat['sale_price']} USDC | Expected cut (50%): ${threat['sensor_cut']} USDC")
    log_event("sensor", f"Pricing threat at ${threat['sale_price']} USDC based on {threat['severity'].upper()} severity")

    print(f"[SENSOR] Paying Enrichment $0.003 USDC to process intel...")
    log_event("payment", "Sensor -> Enrichment: $0.003 USDC to process threat intel")

    tx = send_payment(wallets["sensor"]["id"], wallets["enrichment"]["address"], "0.003")
    print(f"[SENSOR] TX ID: {tx['data']['id']} | State: {tx['data']['state']}")
    log_event("transaction", f"Payment confirmed | TX: {tx['data']['id'][:16]}... | State: {tx['data']['state']}")

    threat["mode"] = "push"
    with open("current_threat.json", "w") as f:
        json.dump(threat, f, indent=2)

    log_event("sensor", "Threat intel packaged and handed to Enrichment Agent")
    return threat

def run_pull_mode(wallets):
    print("[SENSOR - PULL MODE] Received intel request from Enrichment Agent...")
    log_event("sensor", "Pull request received from Enrichment Agent. Checking threat pool...")

    threat = check_for_threats()

    if threat:
        feed = threat.get("feed", "Unknown Feed")
        log_event("sensor", f"Threat found in pool via {feed}: {threat['type'].replace('_',' ').upper()} [{threat['severity'].upper()}]", threat)
        print(f"[SENSOR] Threat available: {threat['type']} | Severity: {threat['severity'].upper()}")
        print(f"[SENSOR] Paying Enrichment $0.003 USDC to process intel...")
        log_event("payment", "Sensor -> Enrichment: $0.003 USDC to process threat intel")

        tx = send_payment(wallets["sensor"]["id"], wallets["enrichment"]["address"], "0.003")
        print(f"[SENSOR] TX ID: {tx['data']['id']} | State: {tx['data']['state']}")
        log_event("transaction", f"Payment confirmed | TX: {tx['data']['id'][:16]}... | State: {tx['data']['state']}")

        threat["mode"] = "pull"
        with open("current_threat.json", "w") as f:
            json.dump(threat, f, indent=2)

        log_event("sensor", "Threat intel packaged and handed to Enrichment Agent")
        return threat
    else:
        print("[SENSOR] No threats currently available in pool.")
        log_event("sensor", "Scan complete. No actionable threats found in current pool.")
        with open("current_threat.json", "w") as f:
            json.dump({"mode": "pull", "available": False}, f, indent=2)
        return None

if __name__ == "__main__":
    with open("wallets.json") as f:
        wallets = json.load(f)

    try:
        with open("pipeline_mode.json") as f:
            mode_data = json.load(f)
        mode = mode_data.get("mode", "push")
    except FileNotFoundError:
        mode = "push"

    if mode == "pull":
        run_pull_mode(wallets)
    else:
        run_push_mode(wallets)