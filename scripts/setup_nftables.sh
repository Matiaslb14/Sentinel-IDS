#!/usr/bin/env bash
set -euo pipefail

echo "[*] Creando tabla/cadena nftables 'sentinel/sentinel_drop' (si no existe)"
sudo nft add table inet sentinel || true
sudo nft add chain inet sentinel sentinel_drop "{ type filter hook input priority 0; }" || true

echo "[*] Asegúrate de tener política por defecto ACCEPT y solo DROP por IPs que agregue el IPS."
sudo nft list chain inet sentinel sentinel_drop || true
echo "[OK] Listo."
