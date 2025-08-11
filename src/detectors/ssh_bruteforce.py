import re
import time
import collections
from pathlib import Path

# Acepta distintos formatos de fallos en sshd:
#  - "Invalid user <user> from <IP> ..."
#  - "Failed password for <user> from <IP> ..."
#  - "authentication failure ... rhost=<IP>"
RE_FROM_IP = re.compile(r"(Failed password|Invalid user).* from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
RE_RHOST   = re.compile(r"authentication failure.*rhost=(?P<ip>\d{1,3}(?:\.\d{1,3}){3})")

class SSHBruteForceDetector:
    def __init__(self, cfg, alerter, ips, stop_event):
        self.log_path = Path(cfg.get("log_path", "/var/log/auth.log"))
        self.window_seconds = int(cfg.get("window_seconds", 120))
        self.fail_threshold = int(cfg.get("fail_threshold", 6))
        self.alerter = alerter
        self.ips = ips
        self.stop_event = stop_event
        self.events = collections.deque()  # (ts, ip)

    def _follow(self):
        # tail -F simple sobre el archivo
        with self.log_path.open("r", errors="ignore") as f:
            f.seek(0, 2)
            while not self.stop_event.is_set():
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    continue
                yield line

    def _extract_ip(self, line: str):
        m = RE_FROM_IP.search(line)
        if m:
            return m.group("ip")
        m = RE_RHOST.search(line)
        if m:
            return m.group("ip")
        return None

    def run(self):
        for line in self._follow():
            ip = self._extract_ip(line)
            if not ip:
                continue

            now = time.time()
            self.events.append((now, ip))

            # purge ventana
            while self.events and now - self.events[0][0] > self.window_seconds:
                self.events.popleft()

            # conteo por IP
            counts = {}
            for ts, ipx in self.events:
                counts[ipx] = counts.get(ipx, 0) + 1

            for ipx, cnt in counts.items():
                if cnt >= self.fail_threshold:
                    self.alerter.alert(
                        title="SSH Brute Force detectado",
                        message=f"IP {ipx} superó {cnt} intentos fallidos en {self.window_seconds}s."
                    )
                    self.ips.block_temporarily(ipx)
                    # limpiar eventos de esa IP para evitar alertas repetidas inmediatas
                    self.events = collections.deque([(ts, i) for ts, i in self.events if i != ipx])
