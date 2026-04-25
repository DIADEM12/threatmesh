import requests
import json
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("CIRCLE_API_KEY")
HEADERS = {"Authorization": f"Bearer {API_KEY}"}

with open("wallets.json") as f:
    wallets = json.load(f)

print("Checking balances...\n")
for agent_name, wallet in wallets.items():
    wallet_id = wallet["id"]
    res = requests.get(f"https://api.circle.com/v1/w3s/wallets/{wallet_id}/balances", headers=HEADERS)
    data = res.json()
    balances = data.get("data", {}).get("tokenBalances", [])
    if balances:
        for b in balances:
            print(f"{agent_name.upper()}: {b['amount']} {b['token']['symbol']}")
    else:
        print(f"{agent_name.upper()}: No balance yet (may take 30 seconds)")