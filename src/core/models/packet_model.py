from PyQt5.QtCore import QAbstractTableModel, Qt, QModelIndex
from datetime import datetime
from scapy.layers.inet import IP, TCP, UDP
from PyQt5.QtGui import QColor

class PacketTableModel(QAbstractTableModel):
    def __init__(self, packets=None):
        super().__init__()
        self.headers = ["№", "Время", "IP Отправителя", "IP Получателя", "Протокол", "Краткая информация"]
        self.packets = packets if packets else []
        self.packet_counter = 1

    def rowCount(self, parent=None):
        return len(self.packets)

    def columnCount(self, parent=None):
        return len(self.headers)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None

        packet = self.packets[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            try:
                if col == 0:
                    return getattr(packet, "fixed_number", index.row() + 1)
                elif col == 1:
                    return datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')
                elif col == 2:
                    ip_layer = packet.getlayer(IP)
                    return ip_layer.src if ip_layer else '-'
                elif col == 3:
                    ip_layer = packet.getlayer(IP)
                    return ip_layer.dst if ip_layer else '-'
                elif col == 4:
                    if packet.haslayer(TCP):
                        return "TCP"
                    elif packet.haslayer(UDP):
                        return "UDP"
                    elif packet.haslayer(IP):
                        return "IP"
                    else:
                        return packet.name if hasattr(packet, 'name') else '-'
                elif col == 5:
                    transport = packet.getlayer(TCP) or packet.getlayer(UDP)
                    src_port = transport.sport if transport else '-'
                    dst_port = transport.dport if transport else '-'
                    flags = self.get_flags(packet)
                    return f"Отправитель: {src_port}, Получатель: {dst_port}, Флаги: {flags}"
            except Exception as e:
                return f"Ошибка: {str(e)}"

        elif role == Qt.BackgroundRole:
            if packet.haslayer(TCP):
                return QColor("#d0e7ff")
            elif packet.haslayer(UDP):
                return QColor("#d2f8d2")
            elif packet.haslayer("ICMP"):
                return QColor("#fff5cc")
            else:
                return None

        return None

    def get_flags(self, packet):
        tcp_layer = packet.getlayer(TCP)
        if tcp_layer and hasattr(tcp_layer, 'flags'):
            flags = tcp_layer.sprintf('%TCP.flags%')
            flag_list = []
            if 'A' in flags:
                flag_list.append('ACK')
            if 'R' in flags:
                flag_list.append('RST')
            if 'S' in flags:
                flag_list.append('SYN')
            if 'F' in flags:
                flag_list.append('FIN')
            return ', '.join(flag_list) if flag_list else '-'
        return '-'

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.headers[section]
        return None

    def add_packet(self, packet):
        self.beginInsertRows(QModelIndex(), self.rowCount(), self.rowCount())
        self.packet_counter += 1
        self.packets.append(packet)
        self.endInsertRows()
