ThreatMesh

A zero-trust threat intelligence marketplace where autonomous AI agents buy, sell, and verify cybersecurity intelligence using USDC nanopayments on Circle's Arc blockchain.

Built for the Circle Hackathon · Agent-to-Agent Payment Loop Track

What Is ThreatMesh?

ThreatMesh is a decentralized, autonomous threat intelligence network. Instead of human analysts manually sharing or purchasing threat data, four autonomous agents operate continuously — scanning for threats, pricing intelligence dynamically, transacting in real time, and verifying data integrity — all without human intervention.
Think of it as a live cybersecurity stock exchange, except the assets are threat intelligence reports and the traders are AI agents paying each other in USDC.

 Architecture

ThreatMesh System:

 Scanner Agent: Detects & classifes threats
 
 Marketplace Agent: Lists intel with dynamic pricing
 
 Buyer Agent: Evaluates & purchases reports
 
 Verifier Agent: Validates intel authenticity
 
                    ┌─────────▼─────────┐
                    │  Circle Arc L1    │
                    │  USDC Nanopayments│
                    │  On-chain Settle  │
                    └───────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │  Flask Backend    │
                    │  REST API         │
                    │  Real-time Events │
                    └─────────▼─────────┘
                              │
                    ┌─────────▼─────────┐
                    │  Live Dashboard   │
                    │  HTML/CSS/JS      │
                    │  Transaction Feed │
                    └───────────────────┘

 The Four Agents
AgentRoleKey BehaviourScannerThreat DetectionContinuously scans and classifies threats, maps them to MITRE ATT&CK frameworkMarketplaceIntelligence BrokerLists threat intel with severity-based dynamic pricing (sub-cent to $0.01)BuyerIntelligence ConsumerAutonomously evaluates and purchases high-value threat reportsVerifierTrust LayerValidates authenticity of purchased intel, flags bad data

The Economic Model
Traditional threat intel sharing fails because:

Gas fees on most blockchains make sub-cent transactions economically unviable
Subscription models mean you pay regardless of value received
Manual processes introduce delay in fast-moving threat environments

ThreatMesh solves this with Circle Nanopayments on Arc L1:
Threat SeverityPrice Per ReportLow$0.001 USDCMedium$0.003 USDCHigh$0.007 USDCCritical$0.010 USDC
 Zero gas overhead ·  Per-action pricing ·  50+ on-chain transactions per demo run

Tech Stack
LayerTechnologyBackendPython, FlaskAgentsPython autonomous agents (threading)FrontendHTML, CSS, JavaScript (live dashboard)BlockchainCircle Arc L1 (EVM-compatible)PaymentsCircle Nanopayments, USDCWalletsCircle Wallet APITunnelingngrokThreat FrameworkMITRE ATT&CK

 Project Structure
threatmesh/
├── agents/               # Autonomous agent logic
├── frontend/             # Live dashboard (HTML/CSS/JS)
├── marketplace/          # Marketplace engine
├── server.py             # Flask backend & API
├── scanner.py            # Threat scanner
├── run_pipeline.py       # Orchestrates full agent pipeline
├── setup_wallets.py      # Circle wallet initialisation
├── fund_wallets.py       # Testnet USDC funding
├── check_balances.py     # Wallet balance checker
├── transaction_log.json  # On-chain transaction history
└── events.json           # System event log

🚀 Getting Started
Prerequisites

Python 3.10+
Circle Developer Account (sign up here)
Arc Testnet access
ngrok (for dashboard tunneling)

Installation
bash# Clone the repo
git clone https://github.com/DIADEM12/threatmesh.git
cd threatmesh

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Add your Circle API keys to .env
Running ThreatMesh
bash# 1. Set up Circle wallets for all agents
python setup_wallets.py

# 2. Fund wallets with testnet USDC
python fund_wallets.py

# 3. Start the Flask server
python server.py

# 4. Launch the agent pipeline
python run_pipeline.py

# 5. Open the live dashboard
# Navigate to http://localhost:5000 or your ngrok URL

Live Dashboard
The real-time dashboard shows:

 Active threat detections as they happen
 Live agent-to-agent USDC transactions
 Transaction volume and severity distribution
 Intel verification status per report


Security Notes

All wallet keys are stored in environment variables — never hardcoded
.env is gitignored
Agents run on Circle's Arc testnet only in this demo

 Author
Diadem Oyelade
Cybersecurity & Networking | Python | Cloud | Security systems

📧 diademoyelade@gmail.com

🔗 LinkedIn: https://linkedin.com/in/diadem-oyelade-a78294279 

📄 License
MIT License — feel free to fork, extend, and build on this.
