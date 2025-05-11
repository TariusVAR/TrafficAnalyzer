from PyQt5.QtWidgets import QMainWindow, QFileDialog, QHeaderView
from PyQt5.uic import loadUi
from PyQt5.QtCore import Qt
from scapy.all import get_working_ifaces
from src.core.main_logic import PacketTrafficAnalyzer

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        loadUi("src/gui/main_window.ui", self)
        self.iface_map = {}

        PacketTrafficAnalyzer.set_main_window(self)

        self.tableViewPacketShowcase.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.tableViewPacketShowcase.setAlternatingRowColors(True)

        self.btnStartSniffing.clicked.connect(self.start_sniffing)
        self.btnStopSniffing.clicked.connect(self.stop_sniffing)
        self.btnImportFromFile.clicked.connect(self.import_packets)
        self.btnExportToFile.clicked.connect(self.export_packets)
        self.btnFilter.clicked.connect(self.apply_filter)
        self.btnRestart.clicked.connect(self.restart_sniffing)

        for iface in get_working_ifaces():
            display_name = f"{iface.name} - {iface.description or 'Без описания'} ({iface.ip or 'нет IP'})"
            self.comboBoxInterface.addItem(display_name)
            self.iface_map[display_name] = iface.name

        self.packet_model = PacketTrafficAnalyzer.get_packet_model()
        self.proxy_model = PacketTrafficAnalyzer.get_proxy_model()
        self.suspicious_model = PacketTrafficAnalyzer.get_suspicious_model()

        self.tableViewPacketShowcase.setModel(self.proxy_model)
        self.tableViewPacketShowcase.setSortingEnabled(True)
        self.tableViewPacketShowcase.sortByColumn(0, Qt.AscendingOrder)
        self.listViewSuspiciousPackets.setModel(self.suspicious_model)

    def start_sniffing(self):
        filter_text = self.textEdit.toPlainText()
        display_name = self.comboBoxInterface.currentText()
        iface = self.iface_map.get(display_name)
        PacketTrafficAnalyzer.start_sniffing(iface, filter_text, self.on_packet_received)
        self.statusbar.showMessage("Захват запущен")

    def stop_sniffing(self):
        PacketTrafficAnalyzer.stop_sniffing()
        self.statusbar.showMessage("Захват остановлен")

    def restart_sniffing(self):
        self.packet_model.packets.clear()
        self.packet_model.layoutChanged.emit()

        PacketTrafficAnalyzer.restart_sniffing()
        self.statusbar.showMessage("Захват перезапущен")


    def apply_filter(self):
        filter_text = self.textEdit.toPlainText()
        PacketTrafficAnalyzer.apply_filter(filter_text)
        self.statusbar.showMessage(f"Фильтр применён: {filter_text}")

    def import_packets(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Импортировать pcap", "", "PCAP files (*.pcap *.cap)")
        if file_name:
            PacketTrafficAnalyzer.import_packets(file_name)

    def export_packets(self):
        file_name, _ = QFileDialog.getSaveFileName(self, "Сохранить pcap", "", "PCAP files (*.pcap)")
        if file_name:
            PacketTrafficAnalyzer.export_packets(file_name)

    def on_packet_received(self, packet):
        self.packet_model.add_packet(packet)
        self.suspicious_model.add_if_suspicious(packet)
        self.tableViewPacketShowcase.scrollToBottom()
