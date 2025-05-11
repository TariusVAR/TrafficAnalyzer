from PyQt5.QtGui import QStandardItemModel, QStandardItem

class SuspiciousListModel(QStandardItemModel):
    def __init__(self):
        super().__init__()
        self.setHorizontalHeaderLabels(["Подозрительные пакеты"])

    def add_if_suspicious(self, packet):
        suspicious_ports = [6666, 1337, 31337]
        suspicious_ips = ["192.168.1.100", "10.0.0.13"]

        if hasattr(packet, 'sport') and packet.sport in suspicious_ports:
            self.appendRow(QStandardItem(f"Подозрительный порт: {packet.sport}"))
        elif hasattr(packet, 'dport') and packet.dport in suspicious_ports:
            self.appendRow(QStandardItem(f"Подозрительный порт: {packet.dport}"))
        elif hasattr(packet, 'src') and packet.src in suspicious_ips:
            self.appendRow(QStandardItem(f"Подозрительный IP: {packet.src}"))
        elif hasattr(packet, 'dst') and packet.dst in suspicious_ips:
            self.appendRow(QStandardItem(f"Подозрительный IP: {packet.dst}"))
