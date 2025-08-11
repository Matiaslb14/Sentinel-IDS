#!/usr/bin/env python3
import os
import time
import threading
import queue
import yaml
from pathlib import Path
from detectors.ssh_bruteforce import SSHBruteForceDetector
from detectors.syn_scan import SynScanDetector
from utils.alerts import TelegramAlerter
from utils.ips import IPSController

CONFIG_PATH = os.environ.get("SENTINEL_IDS_CONFIG", "config.yaml")

def load_config():
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)

def main():
    config = load_config()

    # Alerting
    telegram = TelegramAlerter(
        bot_token=config["telegram"]["bot_token"],
        chat_id=config["telegram"]["chat_id"],
    )

    # IPS
    ips_cfg = config.get("ips", {})
    ips = IPSController(
        enable_blocking=ips_cfg.get("enable_blocking", False),
        block_seconds=int(ips_cfg.get("block_seconds", 900)),
        nftables_chain=ips_cfg.get("nftables_chain", "sentinel_drop"),
        alerter=telegram
    )

    stop_event = threading.Event()

    threads = []

    # SSH brute force detector
    ssh_cfg = config["detectors"]["ssh_bruteforce"]
    if ssh_cfg.get("enabled", True):
        ssh_det = SSHBruteForceDetector(ssh_cfg, telegram, ips, stop_event)
        t = threading.Thread(target=ssh_det.run, daemon=True)
        t.start()
        threads.append(t)

    # SYN scan detector (optional)
    syn_cfg = config["detectors"]["syn_scan"]
    if syn_cfg.get("enabled", False):
        syn_det = SynScanDetector(syn_cfg, telegram, ips, stop_event)
        t = threading.Thread(target=syn_det.run, daemon=True)
        t.start()
        threads.append(t)

    try:
        while any(t.is_alive() for t in threads):
            time.sleep(1)
    except KeyboardInterrupt:
        stop_event.set()
        for t in threads:
            t.join(timeout=2)

if __name__ == "__main__":
    main()
