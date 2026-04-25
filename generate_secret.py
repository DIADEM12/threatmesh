import secrets
import json

# Generate a random 32-byte entity secret
entity_secret = secrets.token_hex(32)
print(f"Your Entity Secret (save this in .env):\n{entity_secret}\n")
print("  Save this somewhere safe — you cannot recover it later!")