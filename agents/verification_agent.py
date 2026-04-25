import requests
import json
import uuid
import os
import hashlib
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

VERIFICATION_REVENUE_SHARE = 0.20
LISTINGS_FILE = "marketplace/listings.json"

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

def verify_threat(threat):
    checks = {
        "has_source_ip":    bool(threat.get("source_ip")),
        "has_timestamp":    bool(threat.get("timestamp")),
        "has_mitre_id":     bool(threat.get("enrichment", {}).get("mitre_id")),
        "has_confidence":   threat.get("confidence_score", 0) > 0.7,
        "severity_valid":   threat.get("severity") in ["low", "medium", "high", "critical"],
        "has_actor":        bool(threat.get("enrichment", {}).get("known_actor")),
        "has_action":       bool(threat.get("enrichment", {}).get("recommended_action")),
        "has_geo":          bool(threat.get("geo")),
        "has_feed":         bool(threat.get("feed"))
    }
    passed = sum(checks.values())
    trust_score = round(passed / len(checks), 2)
    fingerprint = hashlib.sha256(
        json.dumps(threat, sort_keys=True).encode()
    ).hexdigest()[:16]

    return {
        **threat,
        "verification": {
            "checks": checks,
            "trust_score": trust_score,
            "passed": passed,
            "total": len(checks),
            "fingerprint": fingerprint,
            "verified": trust_score >= 0.8
        },
        "verified_at": datetime.now(UTC).isoformat()
    }

def load_listings():
    try:
        with open(LISTINGS_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def save_listing(verified_threat):
    os.makedirs("marketplace", exist_ok=True)
    listings = load_listings()
    listing = {
        "listing_id":   str(uuid.uuid4())[:8],
        "threat_id":    verified_threat["threat_id"],
        "threat_type":  verified_threat["type"],
        "severity":     verified_threat["severity"],
        "sale_price":   verified_threat["sale_price"],
        "mitre_id":     verified_threat["enrichment"]["mitre_id"],
        "tactic":       verified_threat["enrichment"]["tactic"],
        "actor":        verified_threat["enrichment"]["known_actor"],
        "trust_score":  verified_threat["verification"]["trust_score"],
        "fingerprint":  verified_threat["verification"]["fingerprint"],
        "region":       verified_threat.get("geo", {}).get("region", "Unknown"),
        "feed":         verified_threat.get("feed", "Unknown"),
        "status":       "available",
        "listed_at":    datetime.now(UTC).isoformat()
    }
    listings.append(listing)
    with open(LISTINGS_FILE, "w") as f:
        json.dump(listings, f, indent=2)
    return listing

def run_push_mode(wallets, threat):
    print("[VERIFICATION - PUSH MODE] Received enriched intel from Enrichment...")
    log_event("verification", f"Received enriched intel: {threat['type'].replace('_',' ').upper()}")

    verified = verify_threat(threat)
    v = verified["verification"]

    log_event("verification", f"Running {v['total']} verification checks...")
    log_event("verification", f"Checks passed: {v['passed']}/{v['total']} | Trust score: {v['trust_score']} | Fingerprint: {v['fingerprint']}")

    if not v["verified"]:
        log_event("verification", "Intel FAILED verification. Pipeline stopped. No listing created.")
        print("[VERIFICATION] Intel failed verification. Pipeline stopped.")
        return None

    log_event("verification", "Intel PASSED verification. Creating marketplace listing...")
    listing = save_listing(verified)

    log_event("marketplace", f"Intel listed for sale | ID: {listing['listing_id']} | Price: ${listing['sale_price']} USDC | Severity: {listing['severity'].upper()}", listing)
    log_event("verification", f"Notifying Consumer Agent that intel is available for purchase...")

    verified["mode"] = "push"
    verified["listing"] = listing
    with open("current_threat.json", "w") as f:
        json.dump(verified, f, indent=2)

    return verified

def run_pull_mode(wallets):
    print("[VERIFICATION - PULL MODE] Received intel request from Consumer...")
    log_event("verification", "Pull request received from Consumer Agent. Forwarding to Enrichment...")

    log_event("payment", "Verification -> Enrichment: $0.001 USDC to relay request")
    tx = send_payment(
        wallets["verification"]["id"],
        wallets["enrichment"]["address"],
        "0.001"
    )
    log_event("transaction", f"Payment confirmed | TX: {tx['data']['id'][:16]}... | State: {tx['data']['state']}")

    with open("current_threat.json", "w") as f:
        json.dump({"mode": "pull"}, f, indent=2)

    subprocess.run(
        ["python", "agents/enrichment_agent.py"],
        env={**os.environ, "PYTHONIOENCODING": "utf-8"}
    )

    with open("current_threat.json") as f:
        enrichment_response = json.load(f)

    if not enrichment_response.get("available", True):
        log_event("verification", "No threats available in pipeline. Notifying Consumer...")
        with open("current_threat.json", "w") as f:
            json.dump({"mode": "pull", "available": False}, f, indent=2)
        return None

    log_event("verification", "Threat received from Enrichment. Running verification checks...")
    verified = verify_threat(enrichment_response)
    v = verified["verification"]

    log_event("verification", f"Checks passed: {v['passed']}/{v['total']} | Trust score: {v['trust_score']}")

    if not v["verified"]:
        log_event("verification", "Intel failed verification. Notifying Consumer...")
        with open("current_threat.json", "w") as f:
            json.dump({"mode": "pull", "available": False}, f, indent=2)
        return None

    listing = save_listing(verified)
    log_event("marketplace", f"Intel listed | ID: {listing['listing_id']} | Price: ${listing['sale_price']} USDC", listing)
    log_event("verification", "Notifying Consumer Agent that intel is ready for purchase...")

    verified["mode"] = "pull"
    verified["listing"] = listing
    with open("current_threat.json", "w") as f:
        json.dump(verified, f, indent=2)

    return verified

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