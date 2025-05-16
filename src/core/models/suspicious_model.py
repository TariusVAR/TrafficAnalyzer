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

        reasons = []

        suspicious_ports = {23, 2323, 6666, 1337, 31337, 4444, 5555, 6969, 12345, 54321, 21, 22, 139, 445, 80, 443, 9050}
        critical_udp_ports = {1900, 5353, 53, 69}

        suspicious_ips = {"192.168.1.100", "10.0.0.13", "172.16.254.1"}
        tor_ports = {9001, 9030, 9050}
        smb_ports = {139, 445}

        if packet.haslayer(IP):
            ip = packet[IP]
            if ip.src in suspicious_ips:
                reasons.append(f"Источник IP из списка: {ip.src}")
            if ip.dst in suspicious_ips:
                reasons.append(f"Назначение IP из списка: {ip.dst}")
            if hasattr(ip, 'proto') and ip.proto not in [1, 6, 17]:
                reasons.append(f"Редкий IP протокол: {ip.proto}")

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = str(tcp.flags)

            if tcp.sport in suspicious_ports:
                reasons.append(f"Подозрительный исходный порт TCP: {tcp.sport}")
            if tcp.dport in suspicious_ports:
                reasons.append(f"Подозрительный целевой порт TCP: {tcp.dport}")
            if tcp.dport in tor_ports:
                reasons.append(f"Возможный TOR-трафик (порт {tcp.dport})")
            if tcp.dport in smb_ports:
                reasons.append(f"Подозрение на SMB-трафик (порт {tcp.dport})")

            if flags == 'S':
                reasons.append("Возможный SYN-скан")
            if flags in ['FPU', 'FSR', 'SR', 'R', 'FA']:
                reasons.append(f"Странные TCP флаги: {flags}")
            if len(tcp.payload) == 0 and flags in ['S', 'A']:
                reasons.append(f"TCP без полезной нагрузки с флагом {flags}")

        if packet.haslayer(UDP):
            udp = packet[UDP]
            if udp.sport in suspicious_ports:
                reasons.append(f"Подозрительный исходный порт UDP: {udp.sport}")
            if udp.dport in suspicious_ports:
                reasons.append(f"Подозрительный целевой порт UDP: {udp.dport}")
            if udp.dport in critical_udp_ports:
                reasons.append(f"Частый UDP DDoS порт: {udp.dport}")

        if packet.haslayer(ICMP):
            icmp = packet[ICMP]
            if icmp.type == 8:
                reasons.append("ICMP Echo Request (пинг) — возможный скан")

        if packet.haslayer(DNS):
            dns = packet[DNS]
            if dns.qr == 0 and packet.haslayer(DNSQR):
                domain = packet[DNSQR].qname.decode(errors='ignore')
                if any(keyword in domain.lower() for keyword in ['malware', 'botnet', 'example', 'test']):
                    reasons.append(f"DNS-запрос подозрительного домена: {domain}")
                if domain.endswith(".onion."):
                    reasons.append(f"DNS .onion — TOR-домены: {domain}")

        if packet.haslayer(HTTPRequest):
            http = packet[HTTPRequest]
            host = http.Host.decode(errors='ignore') if http.Host else ''
            path = http.Path.decode(errors='ignore') if http.Path else ''
            if any(x in host for x in ['.onion', 'malicious', 'exploit']):
                reasons.append(f"HTTP-запрос на подозрительный хост: {host}")
            if host or path:
                reasons.append(f"HTTP: GET {host}{path}")

        if packet.haslayer(HTTPResponse):
            reasons.append("HTTP-ответ получен — возможная сессия")

        if packet.haslayer(TLSClientHello):
            reasons.append("TLS Client Hello обнаружен")
        if packet.haslayer(TLSServerHello):
            reasons.append("TLS Server Hello обнаружен")

        if packet.haslayer(Ether):
            ether = packet[Ether]
            if ether.dst == "ff:ff:ff:ff:ff:ff":
                reasons.append("Широковещательный MAC-адрес")

        if packet.haslayer(Raw):
            raw_data = bytes(packet[Raw])
            if b'root' in raw_data or b'admin' in raw_data:
                reasons.append("Низкоуровневые данные содержат 'root' или 'admin' — возможный вход")
            if b'USER ' in raw_data or b'PASS ' in raw_data:
                reasons.append("Обнаружен FTP/Telnet логин")

        for reason in reasons:
            print(packet)
            print(type(packet))
            item_text = f"Пакет №{getattr(packet, 'custom_number', '?')}: {reason}"
            self.appendRow(QStandardItem(item_text))

    def clear(self):
        self.removeRows(0, self.rowCount())
