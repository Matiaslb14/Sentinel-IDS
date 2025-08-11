# 🚨 Sentinel IDS/IPS — Monitor de intrusiones ligero para Linux

**Sentinel IDS/IPS** es un sistema de detección y prevención de intrusiones diseñado para entornos Linux, escrito en **Python** y con soporte para **alertas locales** y **bloqueo automático de IPs** usando `nftables`.  

El objetivo es brindar una solución ligera y fácil de implementar para detectar ataques de fuerza bruta SSH y otros eventos sospechosos en tiempo real.

---

## 📌 Características principales
- **Detección en tiempo real** de ataques de fuerza bruta SSH.
- **Soporte para logs de `/var/log/auth.log`** y formatos modernos con `Invalid user`.
- **Bloqueo automático de IPs** por tiempo configurable (IPS) usando `nftables`.
- **Alertas en consola y guardado en `logs/sentinel.log`**.
- **Integración opcional con Telegram** para recibir notificaciones remotas.
- **Configuración sencilla** mediante `config.yaml`.

---

## 🛠️ Requisitos
- Linux con Python 3.10 o superior.
- `nftables` instalado y activo.
- Acceso de root para bloqueo de IPs.
- `rsyslog` habilitado para generar `/var/log/auth.log`:
  ```bash
  sudo apt install rsyslog
  sudo systemctl enable --now rsyslog

## 🚀 Instalación

# 1. Clonar el repositorio
git clone git@github.com:Matiaslb14/06-Sentinel-IDS.git
cd 06-Sentinel-IDS

# 2. Crear entorno virtual e instalar dependencias
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Configurar
cp config.example.yaml config.yaml
nano config.yaml  # ajustar parámetros
⚙️ Configuración
El archivo config.yaml permite personalizar:

telegram:
  bot_token: ""         # Dejar vacío si no se usa Telegram
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

▶️ Ejecución
Modo prueba (consola)

sudo -E .venv/bin/python src/ids.py
El sistema quedará monitoreando eventos y mostrando alertas.

Probar detección de fuerza bruta
En otra terminal:

for i in {1..7}; do \
  ssh -o PreferredAuthentications=password \
      -o PubkeyAuthentication=no \
      -o StrictHostKeyChecking=no \
      -o BatchMode=yes \
      invaliduser@127.0.0.1; \
done

🛡️ Instalación como servicio
Para que Sentinel IDS se ejecute al iniciar el sistema:


sudo ./scripts/setup_nftables.sh
sudo ./scripts/install_service.sh
sudo systemctl status sentinel-ids

📂 Estructura del proyecto
bash
Copiar
Editar
06-Sentinel-IDS/
├── src/                # Código fuente
│   ├── detectors/      # Módulos de detección
│   └── utils/          # Herramientas (alertas, IPS)
├── scripts/            # Scripts auxiliares
├── logs/               # Carpeta de logs
├── config.yaml         # Configuración del sistema
└── README.md
