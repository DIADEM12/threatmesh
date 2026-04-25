import requests
import uuid
import os
import json
from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import base64
import secrets

load_dotenv()

API_KEY = os.getenv("CIRCLE_API_KEY")
ENTITY_SECRET = os.getenv("ENTITY_SECRET")
BASE_URL = "https://api.circle.com/v1/w3s"

HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

AGENTS = ["sensor", "enrichment", "verification", "consumer"]

def get_public_key():
    """Fetch Circle's public key for encrypting entity secret"""
    res = requests.get(f"{BASE_URL}/config/entity/publicKey", headers=HEADERS)
    data = res.json()
    print("Public key response:", data)
    return data["data"]["publicKey"]

def encrypt_entity_secret(public_key_pem: str, entity_secret: str) -> str:
    """Encrypt the entity secret using Circle's public key"""
    # Load Circle's public key
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    
    # Entity secret must be 32 bytes, hex-encoded = 64 chars
    entity_secret_bytes = bytes.fromhex(entity_secret)
    
    # Encrypt with RSA-OAEP
    encrypted = public_key.encrypt(
        entity_secret_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

def create_wallet_set(entity_secret_ciphertext):
    """Create a wallet set to group all agent wallets"""
    body = {
        "idempotencyKey": str(uuid.uuid4()),
        "name": "ThreatMesh Agents",
        "entitySecretCiphertext": entity_secret_ciphertext
    }
    res = requests.post(f"{BASE_URL}/developer/walletSets", json=body, headers=HEADERS)
    data = res.json()
    print("Wallet Set Response:", data)
    return data["data"]["walletSet"]["id"]

def create_wallet(wallet_set_id, agent_name, entity_secret_ciphertext):
    """Create one wallet per agent"""
    body = {
        "idempotencyKey": str(uuid.uuid4()),
        "blockchains": ["ARC-TESTNET"],
        "count": 1,
        "walletSetId": wallet_set_id,
        "entitySecretCiphertext": entity_secret_ciphertext,
        "metadata": [{"name": f"{agent_name}_agent", "refId": agent_name}]
    }
    res = requests.post(f"{BASE_URL}/developer/wallets", json=body, headers=HEADERS)
    data = res.json()
    print(f"\n{agent_name.upper()} Agent Wallet Response:", data)
    
    if "data" in data and "wallets" in data["data"]:
        wallet = data['data']['wallets'][0]
        print(f"  Wallet ID : {wallet['id']}")
        print(f"  Address   : {wallet['address']}")
        return wallet
    return None

if __name__ == "__main__":
    print("Setting up ThreatMesh agent wallets...\n")
    
    # Step 1: Get Circle's public key
    print("Fetching Circle public key...")
    public_key_pem = get_public_key()
    
    # Step 2: Encrypt entity secret
    print("Encrypting entity secret...")
    ciphertext = encrypt_entity_secret(public_key_pem, ENTITY_SECRET)
    print(" Entity secret encrypted\n")
    
    # Step 3: Create wallet set
    print("Creating wallet set...")
    wallet_set_id = create_wallet_set(ciphertext)
    print(f" Wallet set created: {wallet_set_id}\n")
    
    # Step 4: Create one wallet per agent
    wallets = {}
    for agent in AGENTS:
        # Fresh ciphertext per request (required by Circle)
        ciphertext = encrypt_entity_secret(public_key_pem, ENTITY_SECRET)
        wallet = create_wallet(wallet_set_id, agent, ciphertext)
        if wallet:
            wallets[agent] = wallet

    # Step 5: Save wallet info to file
    with open("wallets.json", "w") as f:
        json.dump(wallets, f, indent=2)
    
    print("\n All wallets saved to wallets.json!")
    print(" Next step: Fund these addresses from the Arc testnet faucet")