import requests
import json
import uuid
import os
import subprocess
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

ENRICHMENT_REVENUE_SHARE = 0.30

ENRICHMENT_DB = {
    # RECONNAISSANCE
    "port_scan":          {"tactic": "Reconnaissance",       "mitre_id": "T1046",     "known_actor": "APT-Unknown",  "recommended_action": "Block source IP and increase logging"},
    "network_sweep":      {"tactic": "Reconnaissance",       "mitre_id": "T1018",     "known_actor": "APT-Unknown",  "recommended_action": "Enable network segmentation"},
    "dns_enumeration":    {"tactic": "Reconnaissance",       "mitre_id": "T1590.002", "known_actor": "APT-41",       "recommended_action": "Restrict DNS zone transfers"},
    "subdomain_harvest":  {"tactic": "Reconnaissance",       "mitre_id": "T1596",     "known_actor": "APT-Unknown",  "recommended_action": "Monitor certificate transparency logs"},
    "ssl_cert_recon":     {"tactic": "Reconnaissance",       "mitre_id": "T1596.003", "known_actor": "APT-Unknown",  "recommended_action": "Audit public SSL certificates"},

    # CREDENTIAL ATTACKS
    "brute_force_ssh":    {"tactic": "Credential Access",    "mitre_id": "T1110.001", "known_actor": "APT-28",       "recommended_action": "Enforce MFA and disable password auth on SSH"},
    "brute_force_rdp":    {"tactic": "Credential Access",    "mitre_id": "T1110.001", "known_actor": "APT-29",       "recommended_action": "Disable RDP or enforce NLA with MFA"},
    "credential_stuffing":{"tactic": "Credential Access",    "mitre_id": "T1110.004", "known_actor": "FIN7",         "recommended_action": "Implement rate limiting and CAPTCHA"},
    "password_spray":     {"tactic": "Credential Access",    "mitre_id": "T1110.003", "known_actor": "APT-33",       "recommended_action": "Enable smart lockout and monitor failed logins"},
    "kerberoasting":      {"tactic": "Credential Access",    "mitre_id": "T1558.003", "known_actor": "APT-29",       "recommended_action": "Audit SPNs and enforce strong service account passwords"},

    # WEB APPLICATION
    "sql_injection":      {"tactic": "Initial Access",       "mitre_id": "T1190",     "known_actor": "FIN7",         "recommended_action": "Deploy WAF rule and patch immediately"},
    "xss_injection":      {"tactic": "Initial Access",       "mitre_id": "T1189",     "known_actor": "APT-Unknown",  "recommended_action": "Implement CSP headers and sanitize inputs"},
    "command_injection":  {"tactic": "Execution",            "mitre_id": "T1059",     "known_actor": "APT-41",       "recommended_action": "Sanitize all user inputs, disable shell execution"},
    "path_traversal":     {"tactic": "Initial Access",       "mitre_id": "T1190",     "known_actor": "APT-Unknown",  "recommended_action": "Implement strict path validation"},
    "ssrf_exploit":       {"tactic": "Initial Access",       "mitre_id": "T1190",     "known_actor": "APT-41",       "recommended_action": "Block internal IP ranges in outbound requests"},
    "log4shell_probe":    {"tactic": "Initial Access",       "mitre_id": "T1190",     "known_actor": "APT-41",       "recommended_action": "Patch Log4j immediately - CVE-2021-44228 is critical"},
    "spring4shell_probe": {"tactic": "Initial Access",       "mitre_id": "T1190",     "known_actor": "APT-Unknown",  "recommended_action": "Patch Spring Framework - CVE-2022-22965"},

    # MALWARE & C2
    "malware_beacon":     {"tactic": "Command and Control",  "mitre_id": "T1071",     "known_actor": "Lazarus",      "recommended_action": "Isolate host and begin forensic analysis"},
    "ransomware_c2":      {"tactic": "Command and Control",  "mitre_id": "T1071.001", "known_actor": "LockBit",      "recommended_action": "Emergency isolation and activate IR plan"},
    "botnet_checkin":     {"tactic": "Command and Control",  "mitre_id": "T1102",     "known_actor": "Emotet",       "recommended_action": "Block C2 IPs and scan all endpoints"},
    "trojan_dropper":     {"tactic": "Execution",            "mitre_id": "T1204",     "known_actor": "APT-29",       "recommended_action": "Block hash and quarantine affected systems"},
    "rootkit_install":    {"tactic": "Defense Evasion",      "mitre_id": "T1014",     "known_actor": "APT-41",       "recommended_action": "Full system reimaging required"},
    "keylogger_exfil":    {"tactic": "Collection",           "mitre_id": "T1056.001", "known_actor": "APT-28",       "recommended_action": "Isolate host and reset all credentials"},
    "cryptominer_deploy": {"tactic": "Impact",               "mitre_id": "T1496",     "known_actor": "TeamTNT",      "recommended_action": "Terminate process and patch entry point"},

    # DATA EXFILTRATION
    "data_exfil_ftp":     {"tactic": "Exfiltration",         "mitre_id": "T1048",     "known_actor": "APT-41",       "recommended_action": "Block outbound FTP and audit data access logs"},
    "data_exfil_dns":     {"tactic": "Exfiltration",         "mitre_id": "T1048.001", "known_actor": "APT-29",       "recommended_action": "Deploy DNS monitoring and block suspicious queries"},
    "data_exfil_https":   {"tactic": "Exfiltration",         "mitre_id": "T1048.002", "known_actor": "Lazarus",      "recommended_action": "Inspect TLS traffic and block suspicious endpoints"},
    "db_dump_attempt":    {"tactic": "Exfiltration",         "mitre_id": "T1020",     "known_actor": "FIN7",         "recommended_action": "Block DB port externally and audit queries"},
    "cloud_storage_leak": {"tactic": "Exfiltration",         "mitre_id": "T1537",     "known_actor": "APT-Unknown",  "recommended_action": "Audit S3 bucket policies immediately"},

    # NETWORK ATTACKS
    "ddos_udp_flood":     {"tactic": "Impact",               "mitre_id": "T1498.002", "known_actor": "Killnet",      "recommended_action": "Activate DDoS mitigation and upstream filtering"},
    "ddos_http_flood":    {"tactic": "Impact",               "mitre_id": "T1498.001", "known_actor": "Killnet",      "recommended_action": "Enable rate limiting and CDN protection"},
    "syn_flood":          {"tactic": "Impact",               "mitre_id": "T1498",     "known_actor": "APT-Unknown",  "recommended_action": "Enable SYN cookies on all public-facing servers"},
    "arp_spoofing":       {"tactic": "Credential Access",    "mitre_id": "T1557.002", "known_actor": "APT-Unknown",  "recommended_action": "Enable dynamic ARP inspection on switches"},
    "mitm_attack":        {"tactic": "Collection",           "mitre_id": "T1557",     "known_actor": "APT-29",       "recommended_action": "Enforce certificate pinning and mutual TLS"},

    # APT CAMPAIGNS
    "apt_lateral_move":   {"tactic": "Lateral Movement",     "mitre_id": "T1021",     "known_actor": "APT-29",       "recommended_action": "Enforce least privilege and segment network"},
    "apt_persistence":    {"tactic": "Persistence",          "mitre_id": "T1547",     "known_actor": "APT-41",       "recommended_action": "Audit startup items and scheduled tasks"},
    "apt_spearphish":     {"tactic": "Initial Access",       "mitre_id": "T1566.001", "known_actor": "Lazarus",      "recommended_action": "Block sender domain and train staff"},
    "supply_chain_inject":{"tactic": "Initial Access",       "mitre_id": "T1195",     "known_actor": "APT-29",       "recommended_action": "Audit all third-party dependencies immediately"},
    "watering_hole":      {"tactic": "Initial Access",       "mitre_id": "T1189",     "known_actor": "APT-33",       "recommended_action": "Block compromised domains and scan endpoints"},

    # CLOUD ATTACKS
    "cloud_iam_abuse":    {"tactic": "Privilege Escalation", "mitre_id": "T1078.004", "known_actor": "APT-Unknown",  "recommended_action": "Rotate IAM keys and audit permissions"},
    "s3_bucket_expose":   {"tactic": "Exfiltration",         "mitre_id": "T1530",     "known_actor": "APT-Unknown",  "recommended_action": "Set bucket to private and enable access logging"},
    "api_key_leak":       {"tactic": "Initial Access",       "mitre_id": "T1552.001", "known_actor": "APT-Unknown",  "recommended_action": "Revoke leaked keys and rotate immediately"},
    "oauth_token_theft":  {"tactic": "Credential Access",    "mitre_id": "T1528",     "known_actor": "APT-29",       "recommended_action": "Revoke OAuth tokens and enforce re-authentication"},
    "container_escape":   {"tactic": "Privilege Escalation", "mitre_id": "T1611",     "known_actor": "TeamTNT",      "recommended_action": "Patch container runtime and restrict capabilities"},

    # INSIDER THREATS
    "insider_data_theft": {"tactic": "Exfiltration",         "mitre_id": "T1048",     "known_actor": "Insider",      "recommended_action": "Revoke access immediately and preserve evidence"},
    "privilege_escalation":{"tactic": "Privilege Escalation","mitre_id": "T1068",     "known_actor": "Insider",      "recommended_action": "Patch vulnerability and review access controls"},
    "policy_violation":   {"tactic": "Initial Access",       "mitre_id": "T1078",     "known_actor": "Insider",      "recommended_action": "Review user activity and enforce policies"},
    "after_hours_access": {"tactic": "Initial Access",       "mitre_id": "T1078",     "known_actor": "Insider",      "recommended_action": "Investigate unusual access pattern"},

    # ZERO DAYS
    "zero_day_browser":   {"tactic": "Initial Access",       "mitre_id": "T1189",     "known_actor": "APT-Unknown",  "recommended_action": "Isolate affected systems pending patch"},
    "zero_day_kernel":    {"tactic": "Privilege Escalation", "mitre_id": "T1068",     "known_actor": "APT-Unknown",  "recommended_action": "Emergency patching and system isolation"},
    "zero_day_vpn":       {"tactic": "Initial Access",       "mitre_id": "T1190",     "known_actor": "APT-Unknown",  "recommended_action": "Take VPN offline pending emergency patch"},

    # PHISHING
    "phishing_kit":       {"tactic": "Initial Access",       "mitre_id": "T1566",     "known_actor": "TA453",        "recommended_action": "Block sender domain and run awareness training"},
    "spear_phishing":     {"tactic": "Initial Access",       "mitre_id": "T1566.001", "known_actor": "APT-33",       "recommended_action": "Block sender and alert targeted employees"},
    "vishing_campaign":   {"tactic": "Initial Access",       "mitre_id": "T1566.004", "known_actor": "APT-Unknown",  "recommended_action": "Alert staff and block suspicious numbers"},
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

def enrich_threat(threat):
    enrichment = ENRICHMENT_DB.get(threat["type"], {
        "tactic": "Unknown",
        "mitre_id": "T0000",
        "known_actor": "Unknown",
        "recommended_action": "Investigate manually"
    })
    sale_price = threat.get("sale_price", 0.008)
    enrichment_cut = round(sale_price * ENRICHMENT_REVENUE_SHARE, 6)
    return {
        **threat,
        "enrichment": enrichment,
        "enrichment_cut": enrichment_cut,
        "confidence_score": 0.92,
        "enriched_at": datetime.now(UTC).isoformat()
    }

def run_push_mode(wallets, threat):
    print("[ENRICHMENT - PUSH MODE] Received threat from Sensor Agent...")
    log_event("enrichment", f"Received threat from Sensor: {threat['type'].replace('_',' ').upper()}")

    enriched = enrich_threat(threat)
    e = enriched["enrichment"]

    print(f"[ENRICHMENT] MITRE: {e['mitre_id']} | Tactic: {e['tactic']} | Actor: {e['known_actor']}")
    log_event("enrichment", f"MITRE mapped: {e['mitre_id']} | Tactic: {e['tactic']} | Actor: {e['known_actor']}")
    log_event("enrichment", f"Recommended action: {e['recommended_action']}")
    log_event("enrichment", f"Sale price: ${enriched['sale_price']} USDC | My cut (30%): ${enriched['enrichment_cut']} USDC")

    print(f"[ENRICHMENT] Paying Verification $0.002 USDC to list intel...")
    log_event("payment", "Enrichment -> Verification: $0.002 USDC to list intel for sale")

    tx = send_payment(wallets["enrichment"]["id"], wallets["verification"]["address"], "0.002")
    print(f"[ENRICHMENT] TX ID: {tx['data']['id']} | State: {tx['data']['state']}")
    log_event("transaction", f"Payment confirmed | TX: {tx['data']['id'][:16]}... | State: {tx['data']['state']}")

    enriched["mode"] = "push"
    with open("current_threat.json", "w") as f:
        json.dump(enriched, f, indent=2)

    log_event("enrichment", "Enriched intel handed to Verification Agent for listing")
    return enriched

def run_pull_mode(wallets):
    print("[ENRICHMENT - PULL MODE] Received intel request from Verification...")
    log_event("enrichment", "Pull request received from Verification. Relaying to Sensor Agent...")

    log_event("payment", "Enrichment -> Sensor: $0.001 USDC to check threat pool")
    tx = send_payment(wallets["enrichment"]["id"], wallets["sensor"]["address"], "0.001")
    log_event("transaction", f"Payment confirmed | TX: {tx['data']['id'][:16]}... | State: {tx['data']['state']}")

    with open("pipeline_mode.json", "w") as f:
        json.dump({"mode": "pull"}, f)

    subprocess.run(
        ["python", "agents/sensor_agent.py"],
        env={**os.environ, "PYTHONIOENCODING": "utf-8"}
    )

    with open("current_threat.json") as f:
        sensor_response = json.load(f)

    if not sensor_response.get("available", True):
        log_event("enrichment", "Sensor reports no threats available. Relaying to Verification...")
        with open("current_threat.json", "w") as f:
            json.dump({"mode": "pull", "available": False}, f, indent=2)
        return None

    log_event("enrichment", "Sensor found a threat. Enriching with MITRE ATT&CK context...")
    enriched = enrich_threat(sensor_response)
    e = enriched["enrichment"]

    log_event("enrichment", f"MITRE mapped: {e['mitre_id']} | Tactic: {e['tactic']} | Actor: {e['known_actor']}")
    log_event("enrichment", f"Sale price: ${enriched['sale_price']} USDC | My cut (30%): ${enriched['enrichment_cut']} USDC")
    log_event("payment", "Enrichment -> Verification: $0.002 USDC to list intel for sale")

    tx = send_payment(wallets["enrichment"]["id"], wallets["verification"]["address"], "0.002")
    log_event("transaction", f"Payment confirmed | TX: {tx['data']['id'][:16]}... | State: {tx['data']['state']}")

    enriched["mode"] = "pull"
    with open("current_threat.json", "w") as f:
        json.dump(enriched, f, indent=2)

    log_event("enrichment", "Enriched intel handed to Verification Agent for listing")
    return enriched

if __name__ == "__main__":
    with open("wallets.json") as f:
        wallets = json.load(f)

    with open("current_threat.json") as f:
        threat = json.load(f)

    mode = threat.get("mode", "push")

    if mode == "pull":
        run_pull_mode(wallets)
    else:
        run_push_mode(wallets, threat)