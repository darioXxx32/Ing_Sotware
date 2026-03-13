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

def seed_models():
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE username = 'mluser' LIMIT 1")
            user = cursor.fetchone()
            ml_user_id = user['id'] if user else None

            sample_models = [
                ("IntrusionRNN", "v1.0", "LSTM", "NSL-KDD", 92.30, 91.10, 90.50, 90.80),
                ("IntrusionRNN", "v1.1", "GRU", "CICIDS2017", 94.10, 93.20, 92.80, 93.00),
                ("BaselineMLP", "v0.9", "MLP", "NSL-KDD", 88.50, 87.90, 86.70, 87.20),
            ]

            for model in sample_models:
                cursor.execute("""
                    INSERT INTO models
                    (name, version, model_type, dataset_name, accuracy, precision_score, recall_score, f1_score, created_by)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (*model, ml_user_id))

            conn.commit()
            print("Models inserted successfully.")
    finally:
        conn.close()

if __name__ == '__main__':
    seed_models()
