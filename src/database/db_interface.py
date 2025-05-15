import bcrypt
from datetime import datetime
from scapy.all import Ether
from scapy.layers.inet import IP, TCP, UDP
from src.database.db_connection import get_db_connection

class DBInterface:
    def __init__(self):
        self.conn = get_db_connection()
        self.conn.autocommit = True
        self.cursor = self.conn.cursor()

    def get_user_by_username(self, username):
        try:
            self.cursor.execute(
                "SELECT id, password_hash FROM users WHERE username = %s",
                (username,)
            )
            return self.cursor.fetchone()
        except Exception as e:
            print("DB error (get_user_by_username):", e)
            return None

    def register_user(self, username, password):
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        try:
            self.cursor.execute(
                "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                (username, hashed)
            )
            return True, None
        except Exception as e:
            self.conn.rollback()
            if hasattr(e, 'pgcode') and e.pgcode == '23505':
                return False, "Пользователь с таким именем уже существует"
            return False, str(e)

    def save_packets_to_db(self, user_id, session_name, packets):
        try:
            with self.conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO sessions (user_id, session_name) VALUES (%s, %s) RETURNING id",
                    (user_id, session_name)
                )
                session_id = cur.fetchone()[0]

                for pkt in packets:
                    timestamp = datetime.fromtimestamp(pkt.time)
                    ip_layer = pkt.getlayer(IP)
                    proto = pkt.lastlayer().name if pkt.lastlayer() else 'N/A'
                    src_ip = ip_layer.src if ip_layer else None
                    dst_ip = ip_layer.dst if ip_layer else None
                    src_port = None
                    dst_port = None
                    tcp_flags = None

                    if pkt.haslayer(TCP):
                        tcp = pkt.getlayer(TCP)
                        src_port = tcp.sport
                        dst_port = tcp.dport
                        flags = tcp.sprintf('%TCP.flags%')
                        flag_list = []
                        if 'A' in flags:
                            flag_list.append('ACK')
                        if 'R' in flags:
                            flag_list.append('RST')
                        if 'S' in flags:
                            flag_list.append('SYN')
                        if 'F' in flags:
                            flag_list.append('FIN')
                        tcp_flags = ", ".join(flag_list) if flag_list else None
                    elif pkt.haslayer(UDP):
                        udp = pkt.getlayer(UDP)
                        src_port = udp.sport
                        dst_port = udp.dport

                    raw = bytes(pkt)

                    cur.execute("""
                        INSERT INTO packets (
                            session_id, timestamp, src_ip, dst_ip,
                            protocol, payload, src_port, dst_port, tcp_flags
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        session_id, timestamp, src_ip, dst_ip,
                        proto, raw, src_port, dst_port, tcp_flags
                    ))
        except Exception as e:
            print("DB error (save_packets_to_db):", e)

    def list_sessions(self, user_id):
        try:
            self.cursor.execute(
                "SELECT session_name FROM sessions WHERE user_id = %s",
                (user_id,)
            )
            return [row[0] for row in self.cursor.fetchall()]
        except Exception as e:
            print("DB error (list_sessions):", e)
            return []

    def load_packets_from_db(self, session_name):
        try:
            self.cursor.execute("""
                SELECT timestamp, src_ip, dst_ip, protocol, src_port, dst_port, tcp_flags, payload
                FROM packets
                WHERE session_id = (SELECT id FROM sessions WHERE session_name = %s)
                ORDER BY timestamp ASC
            """, (session_name,))
            rows = self.cursor.fetchall()

            packets_info = []
            for row in rows:
                timestamp, src_ip, dst_ip, protocol, src_port, dst_port, tcp_flags, payload = row
                pkt = Ether(payload)
                packets_info.append({
                    'timestamp': timestamp,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'protocol': protocol,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'tcp_flags': tcp_flags,
                    'packet': pkt,
                })
            return packets_info
        except Exception as e:
            print("DB error (load_packets_from_db):", e)
            return []



