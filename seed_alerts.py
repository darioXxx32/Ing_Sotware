import pymysql
import random

def get_connection():
    return pymysql.connect(
        host="127.0.0.1",
        port=3306,
        user="idsuser",
        password="idspass",
        database="idsdb",
        cursorclass=pymysql.cursors.DictCursor
    )

def seed_alerts():
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id, label, source_ip, dest_ip, protocol
                FROM events
                WHERE label IN ('suspicious', 'attack')
            """)
            events = cursor.fetchall()

            severities = ['medium', 'high', 'critical']

            for event in events:
                title = f"Suspicious activity detected from {event['source_ip']}"
                if event['label'] == 'attack':
                    title = f"Potential attack detected from {event['source_ip']}"

                severity = random.choice(severities)
                description = (
                    f"Event from {event['source_ip']} to {event['dest_ip']} "
                    f"using {event['protocol']} was classified as {event['label']}."
                )

                cursor.execute("""
                    INSERT INTO alerts (event_id, title, severity, status, description)
                    VALUES (%s, %s, %s, 'open', %s)
                """, (event['id'], title, severity, description))

            conn.commit()
            print("Alerts inserted successfully.")
    finally:
        conn.close()

if __name__ == '__main__':
    seed_alerts()