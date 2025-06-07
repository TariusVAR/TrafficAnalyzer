import json
import psycopg2

def get_db_connection():
    config_path='db_config.json'
    with open(config_path, 'r') as f:
        config = json.load(f)

    return psycopg2.connect(
        dbname=config['dbname'],
        user=config['user'],
        password=config['password'],
        host=config['host'],
        port=config['port']
    )

def ensure_tables_exist():
    queries = [
        """
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            user_role VARCHAR(10) NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS sessions (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) NOT NULL,
            session_name VARCHAR(50) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS packets (
            id SERIAL PRIMARY KEY,
            session_id INTEGER REFERENCES sessions(id),
            timestamp TIMESTAMP NOT NULL,
            src_ip VARCHAR(15),
            dst_ip VARCHAR(15),
            protocol TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            tcp_flags TEXT,
            payload BYTEA
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS allowed_rules (
            id SERIAL PRIMARY KEY,
            rule_type VARCHAR(10) CHECK (rule_type IN ('ip', 'port')),
            value VARCHAR(255) NOT NULL
        )
        """
    ]
    conn = get_db_connection()
    cur = conn.cursor()
    for query in queries:
        cur.execute(query)
    conn.commit()
    cur.close()
    conn.close()
