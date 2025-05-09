from src.core.packet_model import PacketTableModel
from src.core.packet_sniffer import PacketSniffer
from src.core.suspicious_model import SuspiciousListModel
from src.core.file_operations import import_packets_from_file, export_packets_to_file

class PacketTrafficAnalyzer:
    packet_model = PacketTableModel()
    suspicious_model = SuspiciousListModel()
    sniffer = None

    @staticmethod
    def start_sniffing(iface, filter_text, on_packet_received):
        PacketTrafficAnalyzer.sniffer = PacketSniffer(iface, filter_text, on_packet_received)
        PacketTrafficAnalyzer.sniffer.start()

    @staticmethod
    def stop_sniffing():
        if PacketTrafficAnalyzer.sniffer:
            PacketTrafficAnalyzer.sniffer.stop()

    @staticmethod
    def restart_sniffing():
        PacketTrafficAnalyzer.stop_sniffing()
        PacketTrafficAnalyzer.packet_model.packets.clear()
        PacketTrafficAnalyzer.packet_model.layoutChanged.emit()
        PacketTrafficAnalyzer.suspicious_model.clear()
        PacketTrafficAnalyzer.sniffer.start()

    @staticmethod
    def apply_filter(filter_text):
        # Фильтрация можно сделать более сложной, если нужно
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
    def get_suspicious_model():
        return PacketTrafficAnalyzer.suspicious_model
