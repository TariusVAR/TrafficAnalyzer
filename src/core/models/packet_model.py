from PyQt5.QtCore import QAbstractTableModel, Qt, QModelIndex
from PyQt5.QtGui import QColor
from datetime import datetime
from scapy.layers.inet import IP, TCP, UDP

class PacketTableModel(QAbstractTableModel):
    def __init__(self, packets=None):
        super().__init__()
        self.headers = [
            "№", "Время", "IP Отправителя", "IP Получателя",
            "Протокол", "Исходный порт", "Целевой порт", "Флаги"
        ]
        self.packets = packets if packets else []
        self.packet_counter = 1

    def rowCount(self, parent=None):
        return len(self.packets)

    def columnCount(self, parent=None):
        return len(self.headers)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None

        item = self.packets[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            try:
                if col == 0:
                    return index.row() + 1
                elif col == 1:
                    return item['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if item['timestamp'] else "-"
                elif col == 2:
                    return item['src_ip'] or "-"
                elif col == 3:
                    return item['dst_ip'] or "-"
                elif col == 4:
                    return item['protocol'] or "-"
                elif col == 5:
                    return item['src_port'] if item['src_port'] is not None else "-"
                elif col == 6:
                    return item['dst_port'] if item['dst_port'] is not None else "-"
                elif col == 7:
                    return item['tcp_flags'] or "-"
            except Exception as e:
                return f"Ошибка: {str(e)}"

        elif role == Qt.BackgroundRole:
            proto = (item.get('protocol') or '').upper()
            if proto == "TCP":
                return QColor("#d0e7ff")
            elif proto == "UDP":
                return QColor("#d2f8d2")
            elif proto == "ICMP":
                return QColor("#fff5cc")
            else:
                return None

        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.headers[section]
        return None

    def add_packet_from_scapy(self, packet):
        packet.custom_number = self.packet_counter
        self.packet_counter += 1

        item = {
            'timestamp': datetime.fromtimestamp(int(packet.time)),
            'src_ip': packet[IP].src if packet.haslayer(IP) else None,
            'dst_ip': packet[IP].dst if packet.haslayer(IP) else None,
            'protocol': 'TCP' if packet.haslayer(TCP) else 'UDP' if packet.haslayer(UDP) else packet.name,
            'src_port': packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport if packet.haslayer(UDP) else None,
            'dst_port': packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport if packet.haslayer(UDP) else None,
            'tcp_flags': packet.sprintf('%TCP.flags%') if packet.haslayer(TCP) else None,
            'packet': packet
        }

        self.beginInsertRows(QModelIndex(), self.rowCount(), self.rowCount())
        self.packets.append(item)
        self.endInsertRows()

    def add_packet_from_db(self, packet_info: dict):
        packet = packet_info['packet']
        packet.custom_number = self.packet_counter
        self.packet_counter += 1    

        item = {
            'timestamp': packet_info['timestamp'],
            'src_ip': packet_info['src_ip'],
            'dst_ip': packet_info['dst_ip'],
            'protocol': packet_info['protocol'],
            'src_port': packet_info['src_port'],
            'dst_port': packet_info['dst_port'],
            'tcp_flags': packet_info['tcp_flags'],
            'packet': packet
        }   

        self.beginInsertRows(QModelIndex(), self.rowCount(), self.rowCount())
        self.packets.append(item)
        self.endInsertRows()

    def reset_packet_counter(self):
        self.packet_counter = 1
