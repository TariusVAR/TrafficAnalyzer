import threading
from scapy.all import sniff

class PacketSniffer:
    def __init__(self, iface, filter_expr, on_packet_callback):
        self.iface = iface
        self.filter_expr = filter_expr
        self.on_packet_callback = on_packet_callback
        self.thread = None
        self._stop_sniffing = threading.Event()

    def start(self):
        self.thread = threading.Thread(target=self._sniff, daemon=True)
        self.thread.start()

    def stop(self):
        self._stop_sniffing.set()

    def _sniff(self):
        sniff(iface=self.iface, filter=self.filter_expr, prn=self._handle_packet, stop_filter=self._should_stop)

    def _handle_packet(self, packet):
        if not self._stop_sniffing.is_set():
            self.on_packet_callback(packet)

    def _should_stop(self, packet):
        return self._stop_sniffing.is_set()
