from werkzeug.security import generate_password_hash
import pymysql

def get_connection():
    return pymysql.connect(
        host="127.0.0.1",
        port=3306,
        user="idsuser",
        password="idspass",
        database="idsdb",
        cursorclass=pymysql.cursors.DictCursor
    )

def seed_answers():
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, username FROM users")
            users = cursor.fetchall()

            sample_answers = {
                "dario": {
                    1: "firulais",
                    2: "ibarra",
                    3: "mathematics"
                },
                "socuser": {
                    1: "toby",
                    2: "quito",
                    4: "maria"
                },
                "netuser": {
                    2: "otavalo",
                    3: "physics",
                    5: "carlos"
                },
                "audituser": {
                    1: "max",
                    4: "sofia",
                    5: "andres"
                },
                "mluser": {
                    2: "ambato",
                    3: "computer science",
                    5: "lucia"
                },
                "operator1": {
                    1: "rocky",
                    4: "elena",
                    5: "pedro"
                }
            }

            for user in users:
                username = user["username"]
                user_id = user["id"]

                if username not in sample_answers:
                    continue

                for question_id, answer in sample_answers[username].items():
                    answer_hash = generate_password_hash(answer)

                    cursor.execute("""
                        INSERT INTO user_security_answers (user_id, question_id, answer_hash)
                        VALUES (%s, %s, %s)
                        ON DUPLICATE KEY UPDATE answer_hash = VALUES(answer_hash)
                    """, (user_id, question_id, answer_hash))

            conn.commit()
            print("Security answers inserted successfully.")

    finally:
        conn.close()

if __name__ == "__main__":
    seed_answers()