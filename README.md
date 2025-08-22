# 🚨 Sentinel IDS/IPS — Lightweight Intrusion Detection & Prevention for Linux

Sentinel IDS/IPS is a lightweight intrusion detection and prevention system designed for Linux environments, written in Python with support for local alerts and automatic IP blocking using nftables.

Its goal is to provide an easy-to-deploy solution for detecting SSH brute-force attacks and other suspicious events in real-time.

📌 Key Features

Real-time detection of SSH brute-force attacks.

Support for /var/log/auth.log and modern Invalid user formats.

Automatic IP blocking for a configurable duration (IPS) using nftables.

Console alerts and persistent logging to logs/sentinel.log.

Optional Telegram integration for remote notifications.

Simple configuration via config.yaml.

🛠 Requirements

Linux with Python 3.10+

nftables installed and active

Root privileges for IP blocking

rsyslog enabled to generate /var/log/auth.log:

sudo apt install rsyslog

sudo systemctl enable --now rsyslog

🚀 Installation

1. Clone the repository

git clone git@github.com:Matiaslb14/06-Sentinel-IDS.git

cd 06-Sentinel-IDS

2. Create virtual environment and install dependencies

python3 -m venv .venv

source .venv/bin/activate

pip install -r requirements.txt

3. Configure

cp config.example.yaml config.yaml

nano config.yaml  # adjust parameters

⚙️ Configuration

The config.yaml file allows customization of:

telegram:
  bot_token: ""         # Leave empty if not using Telegram
  chat_id: ""

ips:
  enable_blocking: true
  block_seconds: 900
  nftables_chain: "sentinel_drop"

detectors:
  ssh_bruteforce:
    enabled: true
    log_path: "/var/log/auth.log"
    window_seconds: 120
    fail_threshold: 6

▶️ Running

Test Mode (Console Output)

sudo -E .venv/bin/python src/ids.py

The system will start monitoring and display alerts in real time.

Test SSH Brute Force Detection (from another terminal):

for i in {1..7}; do \
  ssh -o PreferredAuthentications=password \
      -o PubkeyAuthentication=no \
      -o StrictHostKeyChecking=no \
      -o BatchMode=yes \
      invaliduser@127.0.0.1; \
done

🛡️ Install as a Service

To run Sentinel IDS at system startup:

sudo ./scripts/setup_nftables.sh

sudo ./scripts/install_service.sh

sudo systemctl status sentinel-ids

📂 Project Structure
06-Sentinel-IDS/

├── src/                # Source code
│   ├── detectors/      # Detection modules
│   └── utils/          # Utility functions (alerts, IPS)
├── scripts/            # Helper scripts
├── logs/               # Log storage
├── config.yaml         # System configuration
└── README.md
