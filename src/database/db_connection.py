import psycopg2

def get_db_connection():
    return psycopg2.connect(
        dbname='trafficAnalis',
        user='st1992',
        password='pwd1992',
        host='172.20.7.6',
        port=5432
    )
