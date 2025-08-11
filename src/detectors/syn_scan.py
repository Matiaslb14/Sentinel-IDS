import time
import collections

try:
    from scapy.all import sniff, TCP, IP
except Exception as e:
    sniff = None
    TCP = None
    IP = None

class SynScanDetector:
    def __init__(self, cfg, alerter, ips, stop_event):
        self.window_seconds = int(cfg.get("window_seconds", 60))
        self.port_threshold = int(cfg.get("port_threshold", 15))
        self.iface = cfg.get("iface", "any")
        self.alerter = alerter
        self.ips = ips
        self.stop_event = stop_event
        self.events = collections.deque()  # (timestamp, src, dport)

    def _handle_packet(self, pkt):
        if TCP is None or IP is None:
            return
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            return
        tcp = pkt[TCP]
        ip = pkt[IP]
        # SYN flag set and ACK not set -> typical first packet
        if tcp.flags == "S":
            now = time.time()
            self.events.append((now, ip.src, tcp.dport))

            # purge window
            while self.events and now - self.events[0][0] > self.window_seconds:
                self.events.popleft()

            # count unique dports by src in the window
            per_src = {}
            for ts, src, dport in self.events:
                per_src.setdefault(src, set()).add(dport)

            for src, ports in per_src.items():
                if len(ports) >= self.port_threshold:
                    self.alerter.alert(
                        title="Posible SYN scan",
                        message=f"IP {src} contactó {len(ports)} puertos en {self.window_seconds}s."
                    )
                    self.ips.block_temporarily(src)
                    # limpiar eventos de esa IP
                    self.events = collections.deque([(ts, s, p) for ts, s, p in self.events if s != src])

    def run(self):
        if sniff is None:
            self.alerter.alert("SYN scan deshabilitado", "Scapy no disponible. Instálalo o desactiva este detector.")
            return
        sniff(iface=self.iface, prn=self._handle_packet, store=False, stop_filter=lambda _: self.stop_event.is_set())
