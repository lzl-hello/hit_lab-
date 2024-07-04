from flask import Flask, request, jsonify
import hashlib
import mysql.connector
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# 数据库配置
db_config = {
    'user': 'root',
    'password': 'root',
    'host': 'localhost',
    'database': 'auth_db'
}


def get_db_connection():
    return mysql.connector.connect(**db_config)


def generate_key_from_hash1(hash1):
    salt = b'static_salt_value'  # 应该使用一个固定的静态盐值
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(hash1.encode()))
    return key


@app.route('/authenticate', methods=['POST'])
def authenticate():
    data = request.json
    username = data['username']
    hash2 = data['hash2']
    nonce = data['nonce']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT hash1 FROM users WHERE username = %s", (username,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()

    if row:
        hash1 = row[0]
        hash2_prime = hashlib.sha256((hash1 + nonce).encode()).hexdigest()

        if hash2 == hash2_prime:
            # 加密 nonce
            key = generate_key_from_hash1(hash1)
            fernet = Fernet(key)
            encrypted_nonce = fernet.encrypt(nonce.encode()).decode()
            return jsonify({'encrypted_nonce': encrypted_nonce})

    return jsonify({'error': 'Authentication failed'}), 401


@app.route('/change_password', methods=['POST'])
def change_password():
    data = request.json
    username = data['username']
    old_password = data['old_password']
    new_password = data['new_password']

    old_hash1 = hashlib.sha256((username + old_password).encode()).hexdigest()
    new_hash1 = hashlib.sha256((username + new_password).encode()).hexdigest()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT hash1 FROM users WHERE username = %s", (username,))
    row = cursor.fetchone()

    if row and row[0] == old_hash1:
        cursor.execute("UPDATE users SET hash1 = %s WHERE username = %s", (new_hash1, username))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'status': 'Password changed successfully'})

    cursor.close()
    conn.close()
    return jsonify({'error': 'Old password is incorrect'}), 401


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
