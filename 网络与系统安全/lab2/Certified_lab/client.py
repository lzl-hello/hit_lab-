import hashlib
import random
import requests
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64

def hash_sha256(data):
    return hashlib.sha256(data.encode()).hexdigest()

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

def authenticate(username, password):
    nonce = str(random.randint(100000, 999999))
    print(nonce)
    hash1 = hash_sha256(username + password)
    hash2 = hash_sha256(hash1 + nonce)

    data = {
        'username': username,
        'hash2': hash2,
        'nonce': nonce
    }

    response = requests.post('http://127.0.0.1:5000/authenticate', json=data)
    if response.status_code == 200:
        encrypted_nonce = response.json().get('encrypted_nonce')
        # 解密 encrypted_nonce
        decrypted_nonce = decrypt_nonce(encrypted_nonce, hash1)
        # 将 decrypted_nonce 写入文件
        with open('auth_code.txt', 'w') as file:
            file.write(decrypted_nonce)
        print("Authentication successful, auth code written to file.")
    else:
        print("Authentication failed.")

def decrypt_nonce(encrypted_nonce, hash1):
    key = generate_key_from_hash1(hash1)
    fernet = Fernet(key)
    decrypted_nonce = fernet.decrypt(encrypted_nonce.encode()).decode()
    return decrypted_nonce

def change_password(username, old_password, new_password):
    data = {
        'username': username,
        'old_password': old_password,
        'new_password': new_password
    }

    response = requests.post('http://127.0.0.1:5000/change_password', json=data)
    if response.status_code == 200:
        print("Password changed successfully.")
    else:
        print("Password change failed:", response.json().get('error'))

# 示例
username = input("Enter username: ")
password = input("Enter password: ")

authenticate(username, password)

change_choice = input("Do you want to change your password? (yes/no): ")
if change_choice.lower() == 'yes':
    old_password = password
    new_password = input("Enter new password: ")
    change_password(username, old_password, new_password)
