import requests
import os
import base64
from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

load_dotenv()

API_KEY = os.getenv("CIRCLE_API_KEY")
ENTITY_SECRET = os.getenv("ENTITY_SECRET")

HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Fetch Circle's public key
res = requests.get("https://api.circle.com/v1/w3s/config/entity/publicKey", headers=HEADERS)
public_key_pem = res.json()["data"]["publicKey"]

# Encrypt your entity secret with Circle's public key
public_key = serialization.load_pem_public_key(public_key_pem.encode())
encrypted = public_key.encrypt(
    bytes.fromhex(ENTITY_SECRET),
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

ciphertext = base64.b64encode(encrypted).decode()
print("Paste this into the Circle Console Entity Secret Ciphertext box:\n")
print(ciphertext)