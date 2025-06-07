from PyQt5.QtGui import QStandardItemModel, QStandardItem
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.layers.dns import DNSQR
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.tls.all import TLSClientHello, TLSServerHello
from scapy.packet import Raw
from src.database.db_interface import DBInterface

class SuspiciousListModel(QStandardItemModel):
    def __init__(self):
        super().__init__()
        self.setHorizontalHeaderLabels(["Подозрительные пакеты"])

        self.db = DBInterface()
        self.load_allowed_rules()

        self.suspicious_ports = {23, 2323, 6666, 1337, 31337, 4444, 5555, 6969, 12345, 54321, 21, 22, 139, 445, 80, 443, 9050}
        self.tor_ports = {9001, 9030, 9050}
        self.smb_ports = {139, 445}
        self.ddos_udp_ports = {1900, 5353, 53, 69}
        self.rare_tcp_flags = {'FPU', 'FSR', 'SR', 'R', 'FA'}
        self.suspicious_ips = {"192.168.1.100", "10.0.0.13", "172.16.254.1"}
    
    def load_allowed_rules(self):
        self.allowed_ips = set(self.db.get_allowed_ips())
        self.allowed_ports = set(self.db.get_allowed_ports())

    def add_if_suspicious(self, packet):
        if not packet:
            return

        data = self.extract_packet_data(packet)

        if self.is_allowed(data):
            return

        reasons = self.analyze_packet(data)
        for reason in reasons:
            item_text = f"Пакет №{data.get('custom_number', '?')}: {reason}"
            self.appendRow(QStandardItem(item_text))

    def is_allowed(self, data):
        sp, dp = data['src_port'], data['dst_port']
        sip, dip = data['src_ip'], data['dst_ip']
        return (
            sip in self.allowed_ips or
            dip in self.allowed_ips or
            sp in self.allowed_ports or
            dp in self.allowed_ports
        )

    def extract_packet_data(self, packet):
        return {
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
            'ether_dst': packet[Ether].dst if packet.haslayer(Ether) else '',
            'has': packet.haslayer
        }

    def analyze_packet(self, d):
        reasons = []

        if d['src_ip'] in self.suspicious_ips:
            reasons.append(f"Источник IP из списка: {d['src_ip']}")
        if d['dst_ip'] in self.suspicious_ips:
            reasons.append(f"Назначение IP из списка: {d['dst_ip']}")

        if d['protocol'] == 'TCP':
            self.check_tcp(d, reasons)
        elif d['protocol'] == 'UDP':
            self.check_udp(d, reasons)
        elif d['protocol'] == 'ICMP':
            if d['packet'][ICMP].type == 8:
                reasons.append("ICMP Echo Request (пинг) — возможный скан")

        self.check_dns(d, reasons)
        self.check_http(d, reasons)
        self.check_tls(d, reasons)
        self.check_misc(d, reasons)

        return reasons

    def check_tcp(self, d, reasons):
        sp, dp, flags = d['src_port'], d['dst_port'], d['tcp_flags']
        rb = d['raw_bytes']

        checks = [
            (sp in self.suspicious_ports, f"Подозрительный исходный порт TCP: {sp}"),
            (dp in self.suspicious_ports, f"Подозрительный целевой порт TCP: {dp}"),
            (dp in self.tor_ports, "TOR порт назначения"),
            (dp in self.smb_ports, "SMB порт"),
            (flags == 'S', "Возможный SYN-скан"),
            (flags in self.rare_tcp_flags, f"Редкие TCP флаги: {flags}"),
            (len(rb) == 0 and flags in ['S', 'A'], f"TCP без полезной нагрузки с флагом {flags}")
        ]
        reasons.extend([msg for cond, msg in checks if cond])

    def check_udp(self, d, reasons):
        sp, dp = d['src_port'], d['dst_port']
        if sp in self.suspicious_ports:
            reasons.append(f"Подозрительный исходный порт UDP: {sp}")
        if dp in self.suspicious_ports:
            reasons.append(f"Подозрительный целевой порт UDP: {dp}")
        if dp in self.ddos_udp_ports:
            reasons.append(f"Частый UDP DDoS порт: {dp}")

    def check_dns(self, d, reasons):
        domain = d['dns_query']
        if not domain:
            return
        if any(word in domain.lower() for word in ['malware', 'botnet', 'example', 'test']):
            reasons.append(f"DNS-запрос подозрительного домена: {domain}")
        if domain.endswith(".onion."):
            reasons.append(f"DNS .onion — TOR-домены: {domain}")

    def check_http(self, d, reasons):
        host, path = d['http_host'], d['http_path']
        if host and any(x in host for x in ['.onion', 'malicious', 'exploit']):
            reasons.append(f"HTTP-запрос на подозрительный хост: {host}")
        if host or path:
            reasons.append(f"HTTP: GET {host}{path}")
        if d['has'](HTTPResponse):
            reasons.append("HTTP-ответ получен — возможная сессия")

    def check_tls(self, d, reasons):
        if d['has'](TLSClientHello):
            reasons.append("TLS Client Hello обнаружен")
        if d['has'](TLSServerHello):
            reasons.append("TLS Server Hello обнаружен")

    def check_misc(self, d, reasons):
        rb = d['raw_bytes']
        if d['ether_dst'] == "ff:ff:ff:ff:ff:ff":
            reasons.append("Широковещательный MAC-адрес")
        if any(keyword in rb for keyword in [b'root', b'admin']):
            reasons.append("Payload содержит 'root' или 'admin'")
        if any(keyword in rb for keyword in [b'USER ', b'PASS ']):
            reasons.append("Payload содержит FTP/Telnet логин")
        if d['dst_port'] and d['dst_port'] > 49152:
            reasons.append(f"Высокий динамический порт: {d['dst_port']}")

    def clear(self):
        self.removeRows(0, self.rowCount())
