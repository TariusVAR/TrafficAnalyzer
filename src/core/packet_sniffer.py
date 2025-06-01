from PyQt5.QtCore import QObject, QThread, pyqtSignal
from scapy.all import sniff

class PacketSnifferWorker(QObject):
    packet_received = pyqtSignal(object)
    finished = pyqtSignal()

    def __init__(self, iface, filter_expr):
        super().__init__()
        self.iface = iface
        self.filter_expr = filter_expr
        self._stop = False

    def start_sniffing(self):
        self._stop = False
        while not self._stop:
            sniff(
                iface=self.iface,
                filter=self.filter_expr,
                prn=self._handle_packet,
                timeout=1,
                store=False
            )
        self.finished.emit()

    def _handle_packet(self, packet):
        print(packet.summary())
        if not self._stop:
            self.packet_received.emit(packet)

    def _should_stop(self, packet):
        return self._stop

    def stop(self):
        self._stop = True
