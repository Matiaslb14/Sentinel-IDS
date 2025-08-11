#!/usr/bin/env bash
set -euo pipefail

UNIT=/etc/systemd/system/sentinel-ids.service

echo "[*] Instalando servicio systemd en $UNIT"

sudo tee "$UNIT" >/dev/null <<'EOF'
[Unit]
Description=Sentinel IDS - IDS/IPS ligero con Telegram
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=%h/06-Sentinel-IDS
Environment=SENTINEL_IDS_CONFIG=%h/06-Sentinel-IDS/config.yaml
ExecStart=%h/06-Sentinel-IDS/.venv/bin/python %h/06-Sentinel-IDS/src/ids.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

echo "[*] Recargando systemd y habilitando servicio"
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-ids

echo "[OK] Servicio iniciado. Revisa: sudo systemctl status sentinel-ids"
