from PyQt5.QtCore import QThread, QSortFilterProxyModel, QRegExp, Qt
from PyQt5.QtWidgets import QMessageBox

from src.core.packet_sniffer import PacketSnifferWorker
from src.core.models.packet_model import PacketTableModel
from src.core.models.suspicious_model import SuspiciousListModel
from src.core.file_operations import import_packets_from_file, export_packets_to_file
from src.database.db_interface import DBInterface
from scapy.all import Ether

class PacketTrafficAnalyzer:
    packet_model = PacketTableModel()
    suspicious_model = SuspiciousListModel()
    proxy_model = QSortFilterProxyModel()
    sniffer_worker = None
    sniffer_thread = None
    main_window = None

    @staticmethod
    def set_main_window(window):
        PacketTrafficAnalyzer.main_window = window

    @staticmethod
    def start_sniffing(iface, filter_text, on_packet_received):

        PacketTrafficAnalyzer.packet_model.packets.clear()
        PacketTrafficAnalyzer.packet_model.layoutChanged.emit()
        PacketTrafficAnalyzer.suspicious_model.clear()
        PacketTrafficAnalyzer.packet_model.reset_packet_counter()
        PacketTrafficAnalyzer.sniffer_thread = QThread()

        PacketTrafficAnalyzer.sniffer_worker = PacketSnifferWorker(iface, filter_text)
        PacketTrafficAnalyzer.sniffer_worker.moveToThread(PacketTrafficAnalyzer.sniffer_thread)

        PacketTrafficAnalyzer.sniffer_worker.packet_received.connect(on_packet_received)
        PacketTrafficAnalyzer.sniffer_thread.started.connect(PacketTrafficAnalyzer.sniffer_worker.start_sniffing)
        PacketTrafficAnalyzer.sniffer_worker.finished.connect(PacketTrafficAnalyzer.sniffer_thread.quit)
        PacketTrafficAnalyzer.sniffer_worker.finished.connect(PacketTrafficAnalyzer.sniffer_worker.deleteLater)
        PacketTrafficAnalyzer.sniffer_thread.finished.connect(PacketTrafficAnalyzer.sniffer_thread.deleteLater)

        PacketTrafficAnalyzer.sniffer_thread.start()

    @staticmethod
    def stop_sniffing():
        if PacketTrafficAnalyzer.sniffer_worker:
            PacketTrafficAnalyzer.sniffer_worker.stop()
            PacketTrafficAnalyzer.sniffer_thread.quit()
            PacketTrafficAnalyzer.sniffer_thread.wait()
            PacketTrafficAnalyzer.sniffer_worker = None
            PacketTrafficAnalyzer.sniffer_thread = None

    @staticmethod
    def restart_sniffing(iface_map):
        display_name = PacketTrafficAnalyzer.main_window.comboBoxInterface.currentText()
        iface = iface_map.get(display_name)
        filter_text = ''

        PacketTrafficAnalyzer.stop_sniffing()

        PacketTrafficAnalyzer.packet_model.packets.clear()
        PacketTrafficAnalyzer.packet_model.layoutChanged.emit()
        PacketTrafficAnalyzer.suspicious_model.clear()
        PacketTrafficAnalyzer.packet_model.reset_packet_counter()

        PacketTrafficAnalyzer.start_sniffing(iface, filter_text, PacketTrafficAnalyzer.main_window.on_packet_received)

    @staticmethod
    def apply_filter(self):
        filter_text = self.filterInput.toPlainText().strip()
        filter_type = self.comboBoxFilterOptions.currentText().lower()

        if not filter_text:
            PacketTrafficAnalyzer.proxy_model.setFilterRegExp(QRegExp())
            return

        patterns = [item.strip() for item in filter_text.split(',') if item.strip()]
        if not patterns:
            return

        if filter_type == "ip адрес":
            regex = '|'.join(patterns)
            PacketTrafficAnalyzer.proxy_model.setFilterKeyColumn(-1)
            PacketTrafficAnalyzer.proxy_model.setFilterRegExp(QRegExp(regex, Qt.CaseInsensitive, QRegExp.RegExp))

        elif filter_type == "порт":
            regex = '|'.join(rf'\b{port}\b' for port in patterns)
            PacketTrafficAnalyzer.proxy_model.setFilterKeyColumn(-1)
            PacketTrafficAnalyzer.proxy_model.setFilterRegExp(QRegExp(regex, Qt.CaseInsensitive, QRegExp.RegExp))

        elif filter_type == "протокол":
            regex = '|'.join(proto.upper() for proto in patterns)
            PacketTrafficAnalyzer.proxy_model.setFilterKeyColumn(4)
            PacketTrafficAnalyzer.proxy_model.setFilterRegExp(QRegExp(regex, Qt.CaseInsensitive, QRegExp.RegExp))

        else:
            PacketTrafficAnalyzer.proxy_model.setFilterRegExp(QRegExp())
            return
        
        PacketTrafficAnalyzer.proxy_model.setFilterRegExp(QRegExp(regex, Qt.CaseInsensitive, QRegExp.RegExp))

        if PacketTrafficAnalyzer.proxy_model.rowCount() == 0:
            PacketTrafficAnalyzer.proxy_model.setFilterRegExp(QRegExp())
            QMessageBox.information(self, "Фильтрация", "Совпадений не найдено. Фильтр не применён.")

    # -----file-----
    @staticmethod
    def import_packets(file_name):
        packets = import_packets_from_file(file_name)
        PacketTrafficAnalyzer.packet_model.beginResetModel()
        PacketTrafficAnalyzer.packet_model.packets.clear()
        PacketTrafficAnalyzer.packet_model.reset_packet_counter()
        PacketTrafficAnalyzer.packet_model.endResetModel()
        PacketTrafficAnalyzer.suspicious_model.clear()
        for packet in packets:
            PacketTrafficAnalyzer.packet_model.add_packet_from_scapy(packet)
            PacketTrafficAnalyzer.suspicious_model.add_if_suspicious(packet)

    @staticmethod
    def export_packets(file_name):
        queries = PacketTrafficAnalyzer.packet_model.packets
        packets = [query['packet'] for query in queries]
        export_packets_to_file(file_name, packets)

    # -----database-----
    @staticmethod
    def import_packets_from_db(session_name):
        db = DBInterface()
        packets = db.load_packets_from_db(session_name)

        model = PacketTrafficAnalyzer.packet_model
        model.beginResetModel()
        model.packets.clear()
        model.reset_packet_counter()
        model.endResetModel()
        PacketTrafficAnalyzer.suspicious_model.clear()

        for pkt in packets:
            model.add_packet_from_scapy(pkt)  # pkt — это scapy пакет
            PacketTrafficAnalyzer.suspicious_model.add_if_suspicious(pkt)

    @staticmethod
    def export_packets_to_db(user_id, session_name):
        db = DBInterface()
        db.save_packets_to_db(user_id, session_name, PacketTrafficAnalyzer.packet_model.packets)


    # -----models-----
    @staticmethod
    def get_packet_model():
        return PacketTrafficAnalyzer.packet_model

    @staticmethod
    def get_proxy_model():
        PacketTrafficAnalyzer.proxy_model.setSourceModel(PacketTrafficAnalyzer.packet_model)
        return PacketTrafficAnalyzer.proxy_model

    @staticmethod
    def get_suspicious_model():
        return PacketTrafficAnalyzer.suspicious_model
