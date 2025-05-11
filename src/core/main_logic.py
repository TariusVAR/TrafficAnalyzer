from PyQt5.QtCore import QThread, QSortFilterProxyModel
from src.core.packet_sniffer import PacketSnifferWorker
from src.core.models.packet_model import PacketTableModel
from src.core.models.suspicious_model import SuspiciousListModel
from src.core.file_operations import import_packets_from_file, export_packets_to_file

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

    @staticmethod
    def restart_sniffing():
        PacketTrafficAnalyzer.stop_sniffing()

        PacketTrafficAnalyzer.packet_model.packets.clear()
        PacketTrafficAnalyzer.packet_model.layoutChanged.emit()
        PacketTrafficAnalyzer.suspicious_model.clear()

        iface = PacketTrafficAnalyzer.sniffer_worker.iface
        filter_text = PacketTrafficAnalyzer.sniffer_worker.filter_expr

        main_window = PacketTrafficAnalyzer.main_window
        PacketTrafficAnalyzer.start_sniffing(iface, filter_text, main_window.on_packet_received)

    @staticmethod
    def apply_filter(filter_text):
        # TODO: реализовать фильтрацию уже полученных пакетов
        pass

    @staticmethod
    def import_packets(file_name):
        packets = import_packets_from_file(file_name)
        for packet in packets:
            PacketTrafficAnalyzer.packet_model.add_packet(packet)
            PacketTrafficAnalyzer.suspicious_model.add_if_suspicious(packet)

    @staticmethod
    def export_packets(file_name):
        export_packets_to_file(file_name, PacketTrafficAnalyzer.packet_model.packets)

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
