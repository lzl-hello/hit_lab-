import hashlib

import mysql.connector
from flask import Flask, request, jsonify, render_template
import subprocess
import json
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

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']

    result = subprocess.run(['python', 'client.py', 'login', username, password], capture_output=True, text=True)
    if result.returncode == 0:
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': result.stderr})

@app.route('/change_password', methods=['POST'])
def change_password():
    data = request.json
    username = data['username']
    old_password = data['oldPassword']
    new_password = data['newPassword']

    result = subprocess.run(['python', 'client.py', 'change_password', username, old_password, new_password], capture_output=True, text=True)
    if result.returncode == 0:
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': result.stderr})

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    password = data['password']

    hash1 = hashlib.sha256((username + password).encode()).hexdigest()

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, hash1) VALUES (%s, %s)", (username, hash1))
        conn.commit()
        response = {'success': True}
    except mysql.connector.Error as err:
        response = {'success': False, 'error': str(err)}
    finally:
        cursor.close()
        conn.close()

    return jsonify(response)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
