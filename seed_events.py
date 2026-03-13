import pymysql
import random
from datetime import datetime, timedelta

def get_connection():
    return pymysql.connect(
        host="127.0.0.1",
        port=3306,
        user="idsuser",
        password="idspass",
        database="idsdb",
        cursorclass=pymysql.cursors.DictCursor
    )

def seed_events():
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            base_time = datetime.now()

            labels = ['normal', 'suspicious', 'attack']
            protocols = ['TCP', 'UDP', 'ICMP']
            statuses = ['new', 'reviewed', 'closed']

            for i in range(1, 31):
                timestamp = base_time - timedelta(minutes=i * 5)
                source_ip = f"192.168.1.{random.randint(1, 254)}"
                dest_ip = f"10.0.0.{random.randint(1, 254)}"
                source_port = random.randint(1000, 65000)
                dest_port = random.choice([22, 53, 80, 443, 3306, 8080])
                protocol = random.choice(protocols)
                size = random.randint(64, 1500)
                label = random.choice(labels)
                score = round(random.uniform(0.10, 0.99), 4)
                status = random.choice(statuses)
                raw_log = f"{timestamp} SRC={source_ip}:{source_port} DST={dest_ip}:{dest_port} PROTO={protocol} SIZE={size} LABEL={label} SCORE={score}"

                cursor.execute("""
                    INSERT INTO events
                    (timestamp, source_ip, dest_ip, source_port, dest_port, protocol, size, label, score, status, raw_log)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    timestamp, source_ip, dest_ip, source_port, dest_port,
                    protocol, size, label, score, status, raw_log
                ))

            conn.commit()
            print("Events inserted successfully.")
    finally:
        conn.close()

if __name__ == '__main__':
    seed_events()