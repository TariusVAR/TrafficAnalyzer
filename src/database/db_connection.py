import psycopg2

def get_db_connection():
    return psycopg2.connect(
        dbname='trafficAnalysis',
        user='postgres',
        password='postgres',
        host='localhost',
        port=5432
    )
