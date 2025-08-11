import subprocess
import threading
import time

class IPSController:
    def __init__(self, enable_blocking, block_seconds, nftables_chain, alerter):
        self.enable_blocking = enable_blocking
        self.block_seconds = int(block_seconds)
        self.chain = nftables_chain
        self.alerter = alerter
        self._locks = {}

    def _nft(self, args):
        return subprocess.run(["nft"] + args, capture_output=True, text=True)

    def ensure_chain(self):
        # Create table/chain if not exists
        self._nft(["add", "table", "inet", "sentinel"])
        self._nft(["add", "chain", "inet", "sentinel", self.chain, "{", "type", "filter", "hook", "input", "priority", "0", ";", "}"])
        # Accept default — we'll add explicit drop rules per IP

    def block_temporarily(self, ip):
        if not self.enable_blocking:
            return
        # de-duplicate per IP
        if ip in self._locks:
            return
        self._locks[ip] = True
        t = threading.Thread(target=self._block_worker, args=(ip,), daemon=True)
        t.start()

    def _block_worker(self, ip):
        # add rule
        add = self._nft(["add", "rule", "inet", "sentinel", self.chain, "ip", "saddr", ip, "drop"])
        if add.returncode == 0:
            self.alerter.alert("IPS: IP bloqueada", f"{ip} bloqueada por {self.block_seconds}s.")
        else:
            # chain may not exist; try to create
            self.ensure_chain()
            self._nft(["add", "rule", "inet", "sentinel", self.chain, "ip", "saddr", ip, "drop"])
            self.alerter.alert("IPS: IP bloqueada", f"{ip} bloqueada por {self.block_seconds}s.")

        time.sleep(self.block_seconds)
        self._nft(["delete", "rule", "inet", "sentinel", self.chain, "ip", "saddr", ip, "drop"])
        self.alerter.alert("IPS: IP desbloqueada", f"{ip} desbloqueada.")
        self._locks.pop(ip, None)
