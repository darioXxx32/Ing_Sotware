import pymysql
from werkzeug.security import generate_password_hash

def get_connection():
    return pymysql.connect(
        host="127.0.0.1",
        port=3306,
        user="idsuser",
        password="idspass",
        database="idsdb",
        cursorclass=pymysql.cursors.DictCursor
    )

def looks_hashed(value: str) -> bool:
    return value.startswith("pbkdf2:") or value.startswith("scrypt:")

def migrate_passwords():
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, password_hash FROM users")
            users = cursor.fetchall()

            for user in users:
                current_value = user["password_hash"]
                if current_value and not looks_hashed(current_value):
                    new_hash = generate_password_hash(current_value)
                    cursor.execute(
                        "UPDATE users SET password_hash = %s WHERE id = %s",
                        (new_hash, user["id"])
                    )

            conn.commit()
            print("Password migration completed successfully.")
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_passwords()