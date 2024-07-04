import hashlib
import mysql.connector

# 数据库配置
db_config = {
    'user': 'root',
    'password': 'root',
    'host': 'localhost',
    'database': 'auth_db'
}


def get_db_connection():
    return mysql.connector.connect(**db_config)


def hash_sha256(data):
    return hashlib.sha256(data.encode()).hexdigest()


def store_user(username, password):
    hash1 = hash_sha256(username + password)

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("INSERT INTO users (username, hash1) VALUES (%s, %s)", (username, hash1))
        conn.commit()
        print(f"User {username} added successfully.")
    except mysql.connector.Error as err:
        print(f"Error: {err}")
    finally:
        cursor.close()
        conn.close()


# 用户输入
username = "wyh"
password = "12345678"

# 存储用户数据
store_user(username, password)
