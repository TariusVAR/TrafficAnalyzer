import bcrypt
from scapy.all import Ether
from scapy.packet import Raw
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

    def get_user_role(self, user_id):
        try:
            self.cursor.execute("SELECT user_role FROM users WHERE id = %s", (user_id,))
            row = self.cursor.fetchone()
            return row[0] if row else "user"
        except Exception as e:
            print("DB error (get_user_role):", e)
            return "user"
        
    def get_all_users(self):
        try:
            self.cursor.execute("SELECT id, username FROM users")
            rows = self.cursor.fetchall()
            return [{"id": row[0], "username": row[1]} for row in rows]
        except Exception as e:
            print("DB error (get_all_users):", e)
            return []
    
    def update_user_role(self, user_id, new_role):
        try:
            self.cursor.execute("UPDATE users SET user_role = %s WHERE id = %s", (new_role, user_id))
            self.conn.commit()
            return True
        except Exception as e:
            print("DB error (update_user_role):", e)
            self.conn.rollback()
            return False

    def delete_user(self, user_id):
        try:
            self.cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
            self.conn.commit()
            return True
        except Exception as e:
            print("DB error (delete_user):", e)
            self.conn.rollback()
            return False



    def register_user(self, username, password):
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        try:
            self.cursor.execute(
                "INSERT INTO users (username, password_hash, user_role) VALUES (%s, %s, 'user')",
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
                    timestamp = pkt['timestamp']   
                    packet = pkt['packet']  
                    ip_layer = packet.getlayer(IP)
                    # proto = packet.lastlayer().name if packet.lastlayer() else 'N/A'
                    proto = pkt['protocol']
                    src_ip = ip_layer.src if ip_layer else None
                    dst_ip = ip_layer.dst if ip_layer else None
                    src_port = None
                    dst_port = None
                    tcp_flags = None

                    if packet.haslayer(TCP):
                        tcp = packet.getlayer(TCP)
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
                    elif packet.haslayer(UDP):
                        udp = packet.getlayer(UDP)
                        src_port = udp.sport
                        dst_port = udp.dport
                    
                    payload = bytes(packet)

                    cur.execute("""
                        INSERT INTO packets (
                            session_id, timestamp, src_ip, dst_ip,
                            protocol, payload, src_port, dst_port, tcp_flags
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        session_id, timestamp, src_ip, dst_ip,
                        proto, payload, src_port, dst_port, tcp_flags
                    ))
        except Exception as e:
            print("DB error (save_packets_to_db):", e)

    def list_sessions(self, user_id, user_role='user'):
        try:
            if user_role == 'admin':
                self.cursor.execute("SELECT session_name FROM sessions")
            else:
                self.cursor.execute("SELECT session_name FROM sessions WHERE user_id = %s", (user_id,))
            return [row[0] for row in self.cursor.fetchall()]
        except Exception as e:
            print("DB error (list_sessions):", e)
            return []

    def delete_session(self, session_name):
        try:
            self.cursor.execute("""
                DELETE FROM packets WHERE session_id = (SELECT id FROM sessions WHERE session_name = %s);
                DELETE FROM sessions WHERE session_name = %s;
            """, (session_name, session_name))
        except Exception as e:
            print("DB error (delete_session):", e)
            raise

    def load_packets_from_db(self, session_name, binary=True):
        try:
            self.cursor.execute("""
                SELECT timestamp, src_ip, dst_ip, protocol, src_port, dst_port, tcp_flags, payload
                FROM packets
                WHERE session_id = (SELECT id FROM sessions WHERE session_name = %s)
                ORDER BY timestamp ASC
            """, (session_name,))
            rows = self.cursor.fetchall()

            packets = []
            for i, row in enumerate(rows):
                timestamp, _, _, _, _, _, _, payload = row
                try:
                    packet = Ether(bytes(payload))
                    if IP in packet:
                        packet = packet[IP]
                    packet = packet.__class__(bytes(packet))

                    packet.time = timestamp.timestamp()
                    packet.custom_number = i + 1
                    packets.append(packet)
                except Exception as e:
                    print(f"Ошибка парсинга пакета №{i + 1}: {e}")
            return packets
        except Exception as e:
            print("DB error (load_packets_from_db):", e)
            return []





