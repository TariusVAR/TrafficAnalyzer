from PyQt5.QtGui import QStandardItemModel, QStandardItem
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.tls.all import TLSClientHello, TLSServerHello
from scapy.packet import Raw

class SuspiciousListModel(QStandardItemModel):
    def __init__(self):
        super().__init__()
        self.setHorizontalHeaderLabels(["Подозрительные пакеты"])

    def add_if_suspicious(self, packet):
        if not packet:
            return

        packet_data = self.extract_packet_data(packet)
        reasons = self.analyze_packet(packet_data)

        for reason in reasons:
            item_text = f"Пакет №{packet_data.get('custom_number', '?')}: {reason}"
            self.appendRow(QStandardItem(item_text))

    def add_if_suspicious_bd(self, packet_info: dict):
        if not packet_info:
            return

        reasons = self.analyze_packet(packet_info)

        for reason in reasons:
            item_text = f"Пакет №{packet_info.get('custom_number', '?')}: {reason}"
            self.appendRow(QStandardItem(item_text))

    def extract_packet_data(self, packet):
        data = {
            'packet': packet,
            'custom_number': getattr(packet, 'custom_number', '?'),
            'src_ip': packet[IP].src if packet.haslayer(IP) else None,
            'dst_ip': packet[IP].dst if packet.haslayer(IP) else None,
            'protocol': 'TCP' if packet.haslayer(TCP) else 'UDP' if packet.haslayer(UDP) else 'ICMP' if packet.haslayer(ICMP) else None,
            'src_port': packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport if packet.haslayer(UDP) else None,
            'dst_port': packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport if packet.haslayer(UDP) else None,
            'tcp_flags': str(packet[TCP].flags) if packet.haslayer(TCP) else '',
            'raw_bytes': bytes(packet[Raw]) if packet.haslayer(Raw) else b'',
            'dns_query': packet[DNSQR].qname.decode(errors='ignore') if packet.haslayer(DNSQR) else '',
            'http_host': packet[HTTPRequest].Host.decode(errors='ignore') if packet.haslayer(HTTPRequest) and packet[HTTPRequest].Host else '',
            'http_path': packet[HTTPRequest].Path.decode(errors='ignore') if packet.haslayer(HTTPRequest) and packet[HTTPRequest].Path else '',
            'ether_dst': packet[Ether].dst if packet.haslayer(Ether) else ''
        }
        data['has'] = lambda layer: packet.haslayer(layer)
        return data

    def analyze_packet(self, data: dict):
        reasons = []

        suspicious_ports = {23, 2323, 6666, 1337, 31337, 4444, 5555, 6969, 12345, 54321, 21, 22, 139, 445, 80, 443, 9050}
        tor_ports = {9001, 9030, 9050}
        smb_ports = {139, 445}
        ddos_udp_ports = {1900, 5353, 53, 69}
        rare_tcp_flags = {'FPU', 'FSR', 'SR', 'R', 'FA'}
        suspicious_ips = {"192.168.1.100", "10.0.0.13", "172.16.254.1"}

        src_ip = data.get('src_ip')
        dst_ip = data.get('dst_ip')
        src_port = data.get('src_port')
        dst_port = data.get('dst_port')
        proto = data.get('protocol', '')
        flags = data.get('tcp_flags', '')
        raw_bytes = data.get('raw_bytes', b'')

        if src_ip in suspicious_ips:
            reasons.append(f"Источник IP из списка: {src_ip}")
        if dst_ip in suspicious_ips:
            reasons.append(f"Назначение IP из списка: {dst_ip}")

        if proto == 'TCP':
            if src_port in suspicious_ports:
                reasons.append(f"Подозрительный исходный порт TCP: {src_port}")
            if dst_port in suspicious_ports:
                reasons.append(f"Подозрительный целевой порт TCP: {dst_port}")
            if dst_port in tor_ports:
                reasons.append("TOR порт назначения")
            if dst_port in smb_ports:
                reasons.append("SMB порт")
            if flags == 'S':
                reasons.append("Возможный SYN-скан")
            if flags in rare_tcp_flags:
                reasons.append(f"Редкие TCP флаги: {flags}")
            if len(raw_bytes) == 0 and flags in ['S', 'A']:
                reasons.append(f"TCP без полезной нагрузки с флагом {flags}")

        elif proto == 'UDP':
            if src_port in suspicious_ports:
                reasons.append(f"Подозрительный исходный порт UDP: {src_port}")
            if dst_port in suspicious_ports:
                reasons.append(f"Подозрительный целевой порт UDP: {dst_port}")
            if dst_port in ddos_udp_ports:
                reasons.append(f"Частый UDP DDoS порт: {dst_port}")

        elif proto == 'ICMP' and data.get('packet') and data['packet'].haslayer(ICMP):
            if data['packet'][ICMP].type == 8:
                reasons.append("ICMP Echo Request (пинг) — возможный скан")

        domain = data.get('dns_query', '')
        if domain:
            if any(keyword in domain.lower() for keyword in ['malware', 'botnet', 'example', 'test']):
                reasons.append(f"DNS-запрос подозрительного домена: {domain}")
            if domain.endswith(".onion."):
                reasons.append(f"DNS .onion — TOR-домены: {domain}")

        host = data.get('http_host', '')
        path = data.get('http_path', '')
        if host:
            if any(x in host for x in ['.onion', 'malicious', 'exploit']):
                reasons.append(f"HTTP-запрос на подозрительный хост: {host}")
        if host or path:
            reasons.append(f"HTTP: GET {host}{path}")

        if data.get('has', lambda _: False)(HTTPResponse):
            reasons.append("HTTP-ответ получен — возможная сессия")

        if data.get('has', lambda _: False)(TLSClientHello):
            reasons.append("TLS Client Hello обнаружен")
        if data.get('has', lambda _: False)(TLSServerHello):
            reasons.append("TLS Server Hello обнаружен")

        if data.get('ether_dst') == "ff:ff:ff:ff:ff:ff":
            reasons.append("Широковещательный MAC-адрес")

        if b'root' in raw_bytes or b'admin' in raw_bytes:
            reasons.append("Payload содержит 'root' или 'admin'")
        if b'USER ' in raw_bytes or b'PASS ' in raw_bytes:
            reasons.append("Payload содержит FTP/Telnet логин")

        if dst_port and dst_port > 49152:
            reasons.append(f"Высокий динамический порт: {dst_port}")

        return reasons

    def clear(self):
        self.removeRows(0, self.rowCount())
