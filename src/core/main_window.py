from PyQt5.QtWidgets import QMainWindow, QFileDialog, QHeaderView, QTreeWidgetItem
from PyQt5.uic import loadUi
from PyQt5.QtCore import Qt
from scapy.all import get_working_ifaces
from src.core.main_logic import PacketTrafficAnalyzer
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime

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

        self.tableViewPacketShowcase.selectionModel().selectionChanged.connect(self.on_row_selected)
        self.treeViewPacketInfo.setHeaderLabels(["Поле", "Значение"])
        header = self.treeViewPacketInfo.header()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.Stretch)

    def start_sniffing(self):
        self.btnStartSniffing.setEnabled(False)
        self.btnStopSniffing.setEnabled(True)

        filter_text = ''
        display_name = self.comboBoxInterface.currentText()
        iface = self.iface_map.get(display_name)
        PacketTrafficAnalyzer.start_sniffing(iface, filter_text, self.on_packet_received)
        self.statusbar.showMessage("Захват запущен")

    def stop_sniffing(self):
        PacketTrafficAnalyzer.stop_sniffing()
        self.statusbar.showMessage("Захват остановлен")

        self.btnStartSniffing.setEnabled(True)
        self.btnStopSniffing.setEnabled(False)

    def restart_sniffing(self):
        self.packet_model.packets.clear()
        self.packet_model.layoutChanged.emit()

        iface_map = self.iface_map

        self.treeViewPacketInfo.clear()
        self.btnStartSniffing.setEnabled(False)
        self.btnStopSniffing.setEnabled(True)
        PacketTrafficAnalyzer.restart_sniffing(iface_map)
        self.statusbar.showMessage("Захват перезапущен")


    def apply_filter(self):
        filter_text = self.filterInput.toPlainText()
        PacketTrafficAnalyzer.apply_filter(self)
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



# qtreewidget with packet info methods

    def on_row_selected(self, selected, deselected):
        proxy_index = self.tableViewPacketShowcase.selectionModel().currentIndex()
        if not proxy_index.isValid():
            return

        source_index = self.proxy_model.mapToSource(proxy_index)
        packet = self.packet_model.packets[source_index.row()]

        self.treeViewPacketInfo.clear()
        self.treeViewPacketInfo.setHeaderLabels(["Поле", "Значение"])

        root = QTreeWidgetItem(self.treeViewPacketInfo)
        root.setText(0, f"Пакет №{packet.custom_number}")

        self.add_tree_item(root, "Время", datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S'))
        self.add_tree_item(root, "Сводка", packet.summary())

        self.add_packet_layers_to_tree(root, packet)

        self.treeViewPacketInfo.expandItem(root)

    def add_packet_layers_to_tree(self, parent_item, packet):
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.l2 import Ether

        def add_fields(item, layer):
            for field_name, value in layer.fields.items():
                sub_item = QTreeWidgetItem(item)
                sub_item.setText(0, str(field_name))
                sub_item.setText(1, str(value))

        current_layer = packet
        visited_layers = set()

        while current_layer:
            layer_name = current_layer.name
            if layer_name in visited_layers:
                break 
            visited_layers.add(layer_name)

            layer_item = QTreeWidgetItem(parent_item)
            layer_item.setText(0, layer_name)

            # Ethernet 
            if current_layer.haslayer(Ether):
                ether = current_layer.getlayer(Ether)
                ether_item = QTreeWidgetItem(layer_item)
                ether_item.setText(0, "Ethernet")
                self.add_tree_item(ether_item, "Source MAC", ether.src)
                self.add_tree_item(ether_item, "Destination MAC", ether.dst)
                self.add_tree_item(ether_item, "Type", hex(ether.type))

            # IP 
            if current_layer.haslayer(IP):
                ip = current_layer.getlayer(IP)
                ip_item = QTreeWidgetItem(layer_item)
                ip_item.setText(0, "IP Header")
                self.add_tree_item(ip_item, "Version", ip.version)
                self.add_tree_item(ip_item, "Header Length", ip.ihl)
                self.add_tree_item(ip_item, "TTL", ip.ttl)
                self.add_tree_item(ip_item, "Protocol", ip.proto)
                self.add_tree_item(ip_item, "Source IP", ip.src)
                self.add_tree_item(ip_item, "Destination IP", ip.dst)
                self.add_tree_item(ip_item, "Flags", ip.flags)

            # TCP 
            if current_layer.haslayer(TCP):
                tcp = current_layer.getlayer(TCP)
                tcp_item = QTreeWidgetItem(layer_item)
                tcp_item.setText(0, "TCP Header")
                self.add_tree_item(tcp_item, "Source Port", tcp.sport)
                self.add_tree_item(tcp_item, "Destination Port", tcp.dport)
                self.add_tree_item(tcp_item, "Sequence Number", tcp.seq)
                self.add_tree_item(tcp_item, "Acknowledgment Number", tcp.ack)
                self.add_tree_item(tcp_item, "Flags", tcp.flags)
                self.add_tree_item(tcp_item, "Window Size", tcp.window)

            # UDP 
            if current_layer.haslayer(UDP):
                udp = current_layer.getlayer(UDP)
                udp_item = QTreeWidgetItem(layer_item)
                udp_item.setText(0, "UDP Header")
                self.add_tree_item(udp_item, "Source Port", udp.sport)
                self.add_tree_item(udp_item, "Destination Port", udp.dport)
                self.add_tree_item(udp_item, "Length", udp.len)

            # ICMP 
            if current_layer.haslayer(ICMP):
                icmp = current_layer.getlayer(ICMP)
                icmp_item = QTreeWidgetItem(layer_item)
                icmp_item.setText(0, "ICMP Header")
                self.add_tree_item(icmp_item, "Type", icmp.type)
                self.add_tree_item(icmp_item, "Code", icmp.code)

            if not any(current_layer.haslayer(l) for l in [Ether, IP, TCP, UDP, ICMP]):
                add_fields(layer_item, current_layer)

            current_layer = current_layer.payload


    def add_tree_item(self, parent, label, value):
        item = QTreeWidgetItem(parent)
        item.setText(0, label)
        item.setText(1, str(value))