import requests
import json
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("CIRCLE_API_KEY")
HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Load wallets from file
with open("wallets.json") as f:
    wallets = json.load(f)

def fund_wallet(agent_name, address):
    body = {
        "address": address,
        "blockchain": "ARC-TESTNET",
        "native": True,   # for gas
        "usdc": True      # for payments
    }
    res = requests.post("https://api.circle.com/v1/faucet/drips", json=body, headers=HEADERS)
    if res.status_code == 204:
        print(f" {agent_name.upper()} funded successfully!")
    else:
        print(f" {agent_name.upper()} failed: {res.status_code} - {res.text}")

if __name__ == "__main__":
    print("Funding all agent wallets from Arc testnet faucet...\n")
    for agent_name, wallet in wallets.items():
        fund_wallet(agent_name, wallet["address"])
    print("\n Done! Run check_balances.py to verify funds arrived.")