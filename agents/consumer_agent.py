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

QUERY_FEE = 0.002
LOG_FILE = "transaction_log.json"

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

def load_log():
    try:
        with open(LOG_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def save_log(entry):
    log = load_log()
    log.append(entry)
    with open(LOG_FILE, "w") as f:
        json.dump(log, f, indent=2)

def mark_listing_sold(listing_id):
    try:
        with open("marketplace/listings.json") as f:
            listings = json.load(f)
        for listing in listings:
            if listing["listing_id"] == listing_id:
                listing["status"] = "sold"
                listing["sold_at"] = datetime.now(UTC).isoformat()
        with open("marketplace/listings.json", "w") as f:
            json.dump(listings, f, indent=2)
    except FileNotFoundError:
        pass

def get_wallet_balances(wallets):
    """Fetch current USDC balance for each agent wallet"""
    balances = {}
    for agent_name, wallet in wallets.items():
        try:
            res = requests.get(
                f"{BASE_URL}/wallets/{wallet['id']}/balances",
                headers={"Authorization": f"Bearer {API_KEY}"}
            )
            data = res.json()
            token_balances = data.get("data", {}).get("tokenBalances", [])
            if token_balances:
                balances[agent_name] = float(token_balances[0]["amount"])
            else:
                balances[agent_name] = 0.0
        except Exception:
            balances[agent_name] = 0.0
    return balances

def buy_intel(wallets, threat):
    sale_price = threat["sale_price"]
    listing_id = threat["listing"]["listing_id"]

    log_event("consumer", f"Purchase decision: APPROVED | Listing: {listing_id} | Price: ${sale_price} USDC")
    log_event("payment", f"Consumer -> Verification: ${sale_price} USDC (full purchase price)")

    tx = send_payment(
        wallets["consumer"]["id"],
        wallets["verification"]["address"],
        str(sale_price)
    )
    print(f"[CONSUMER] TX ID: {tx['data']['id']} | State: {tx['data']['state']}")
    log_event("transaction", f"Purchase payment confirmed | TX: {tx['data']['id'][:16]}... | State: {tx['data']['state']}")

    mark_listing_sold(listing_id)
    log_event("marketplace", f"Listing {listing_id} marked as SOLD")

    verification_cut = round(sale_price * 0.20, 6)
    enrichment_cut = round(sale_price * 0.30, 6)
    sensor_cut = round(sale_price * 0.50, 6)
    enrichment_and_sensor = round(sale_price - verification_cut, 6)

    log_event("consumer", f"Triggering revenue distribution up the chain...")
    log_event("payment", f"Verification -> Enrichment: ${enrichment_and_sensor} USDC (80% revenue share)")

    tx2 = send_payment(
        wallets["verification"]["id"],
        wallets["enrichment"]["address"],
        str(enrichment_and_sensor)
    )
    log_event("transaction", f"Revenue share confirmed | TX: {tx2['data']['id'][:16]}... | State: {tx2['data']['state']}")

    log_event("payment", f"Enrichment -> Sensor: ${sensor_cut} USDC (50% revenue share)")
    tx3 = send_payment(
        wallets["enrichment"]["id"],
        wallets["sensor"]["address"],
        str(sensor_cut)
    )
    log_event("transaction", f"Revenue share confirmed | TX: {tx3['data']['id'][:16]}... | State: {tx3['data']['state']}")

    log_event("consumer", f"Revenue distribution complete | Verification: ${verification_cut} | Enrichment: ${enrichment_cut} | Sensor: ${sensor_cut}")

    # Fetch updated balances
    balances = get_wallet_balances(wallets)
    log_event("balances", "Wallet balances updated after transaction", balances)

    return {
        "purchase_tx": tx["data"]["id"],
        "verification_cut": verification_cut,
        "enrichment_cut": enrichment_cut,
        "sensor_cut": sensor_cut,
        "total_paid": sale_price,
        "balances": balances
    }

def run_push_mode(wallets, threat):
    print("[CONSUMER - PUSH MODE] Received notification from Verification...")
    log_event("consumer", f"Notification received: Intel available for purchase")
    log_event("consumer", f"Reviewing listing: {threat['type'].replace('_',' ').upper()} | Severity: {threat['severity'].upper()} | Price: ${threat['sale_price']} USDC | Trust: {threat['verification']['trust_score']}")

    should_buy = (
        threat["verification"]["trust_score"] >= 0.8 and
        threat["severity"] in ["medium", "high", "critical"]
    )

    if not should_buy:
        log_event("consumer", f"Purchase decision: DECLINED | Trust score or severity below threshold")
        print("[CONSUMER] Intel does not meet purchase criteria. Skipping.")
        log_entry = {
            "pipeline_run": len(load_log()) + 1,
            "mode": "push",
            "action": "skipped",
            "threat_type": threat["type"],
            "severity": threat["severity"],
            "reason": "Below purchase threshold",
            "completed_at": datetime.now(UTC).isoformat()
        }
        save_log(log_entry)
        return

    purchase = buy_intel(wallets, threat)

    log_event("consumer", f"Applying defensive action: {threat['enrichment']['recommended_action']}")
    log_event("consumer", f"Pipeline complete | Total cost: ${purchase['total_paid']} USDC | Savings vs Ethereum: ~99%")

    log_entry = {
        "pipeline_run": len(load_log()) + 1,
        "mode": "push",
        "action": "purchased",
        "threat_type": threat["type"],
        "source_ip": threat["source_ip"],
        "severity": threat["severity"],
        "mitre_id": threat["enrichment"]["mitre_id"],
        "actor": threat["enrichment"]["known_actor"],
        "trust_score": threat["verification"]["trust_score"],
        "fingerprint": threat["verification"]["fingerprint"],
        "sale_price": purchase["total_paid"],
        "feed": threat.get("feed", "Unknown"),
        "geo": threat.get("geo", {}),
        "revenue_share": {
            "verification": purchase["verification_cut"],
            "enrichment": purchase["enrichment_cut"],
            "sensor": purchase["sensor_cut"]
        },
        "defensive_action": threat["enrichment"]["recommended_action"],
        "balances": purchase.get("balances", {}),
        "completed_at": datetime.now(UTC).isoformat()
    }
    save_log(log_entry)
    print(f"[CONSUMER] Pipeline run #{log_entry['pipeline_run']} complete.")

def run_pull_mode(wallets):
    print("[CONSUMER - PULL MODE] Requesting intel update from marketplace...")
    log_event("consumer", f"Initiating PULL request. Paying query fee of ${QUERY_FEE} USDC to Verification...")
    log_event("payment", f"Consumer -> Verification: ${QUERY_FEE} USDC (query fee)")

    tx = send_payment(
        wallets["consumer"]["id"],
        wallets["verification"]["address"],
        str(QUERY_FEE)
    )
    log_event("transaction", f"Query fee confirmed | TX: {tx['data']['id'][:16]}... | State: {tx['data']['state']}")

    with open("current_threat.json", "w") as f:
        json.dump({"mode": "pull"}, f, indent=2)

    subprocess.run(
        ["python", "agents/verification_agent.py"],
        env={**os.environ, "PYTHONIOENCODING": "utf-8"}
    )

    with open("current_threat.json") as f:
        response = json.load(f)

    if not response.get("available", True):
        log_event("consumer", "Response received: No threats currently available in marketplace")
        log_event("consumer", f"Query fee of ${QUERY_FEE} USDC retained by agents for processing")
        print("[CONSUMER] No threats available.")
        log_entry = {
            "pipeline_run": len(load_log()) + 1,
            "mode": "pull",
            "action": "no_update",
            "query_fee_paid": QUERY_FEE,
            "completed_at": datetime.now(UTC).isoformat()
        }
        save_log(log_entry)
        return

    log_event("consumer", f"Response received: Intel available | {response['type'].replace('_',' ').upper()} | ${response['sale_price']} USDC")

    purchase = buy_intel(wallets, response)

    log_event("consumer", f"Applying defensive action: {response['enrichment']['recommended_action']}")
    log_event("consumer", f"Pipeline complete | Total cost: ${purchase['total_paid'] + QUERY_FEE} USDC (including query fee)")

    log_entry = {
        "pipeline_run": len(load_log()) + 1,
        "mode": "pull",
        "action": "purchased",
        "threat_type": response["type"],
        "source_ip": response["source_ip"],
        "severity": response["severity"],
        "mitre_id": response["enrichment"]["mitre_id"],
        "actor": response["enrichment"]["known_actor"],
        "trust_score": response["verification"]["trust_score"],
        "sale_price": purchase["total_paid"],
        "query_fee_paid": QUERY_FEE,
        "feed": response.get("feed", "Unknown"),
        "geo": response.get("geo", {}),
        "revenue_share": {
            "verification": purchase["verification_cut"],
            "enrichment": purchase["enrichment_cut"],
            "sensor": purchase["sensor_cut"]
        },
        "defensive_action": response["enrichment"]["recommended_action"],
        "balances": purchase.get("balances", {}),
        "completed_at": datetime.now(UTC).isoformat()
    }
    save_log(log_entry)
    print(f"[CONSUMER] Pipeline run #{log_entry['pipeline_run']} complete.")

if __name__ == "__main__":
    with open("wallets.json") as f:
        wallets = json.load(f)

    import sys
    mode = sys.argv[1] if len(sys.argv) > 1 else "push"

    if mode == "pull":
        run_pull_mode(wallets)
    else:
        with open("current_threat.json") as f:
            threat = json.load(f)
        run_push_mode(wallets, threat)