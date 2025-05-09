from PyQt5.QtCore import QAbstractTableModel, Qt, QModelIndex

class PacketTableModel(QAbstractTableModel):
    def __init__(self, packets=None):
        super().__init__()
        self.headers = ["№", "Время", "Источник", "Назначение", "Протокол", "Размер"]
        self.packets = packets if packets else []

    def rowCount(self, parent=None):
        return len(self.packets)

    def columnCount(self, parent=None):
        return len(self.headers)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or role != Qt.DisplayRole:
            return None
        packet = self.packets[index.row()]
        col = index.column()
        try:
            if col == 0:
                return str(index.row() + 1)
            elif col == 1:
                return str(packet.time)
            elif col == 2:
                return packet[0].src if hasattr(packet[0], 'src') else '-'
            elif col == 3:
                return packet[0].dst if hasattr(packet[0], 'dst') else '-'
            elif col == 4:
                return packet.name
            elif col == 5:
                return len(packet)
        except Exception:
            return "Ошибка"

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.headers[section]
        return None

    def add_packet(self, packet):
        self.beginInsertRows(QModelIndex(), self.rowCount(), self.rowCount())
        self.packets.append(packet)
        self.endInsertRows()
