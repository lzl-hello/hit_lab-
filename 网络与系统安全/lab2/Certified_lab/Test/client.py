import hashlib
import random
import requests
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import sys

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
        decrypted_nonce = decrypt_nonce(encrypted_nonce, hash1)
        with open('auth_code.txt', 'w') as file:
            file.write(decrypted_nonce)
        return True
    else:
        return False

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
        return True
    else:
        return False

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python client.py <command> [args]")
        sys.exit(1)

    command = sys.argv[1]

    if command == 'login':
        if len(sys.argv) != 4:
            print("Usage: python client.py login <username> <password>")
            sys.exit(1)
        username = sys.argv[2]
        password = sys.argv[3]
        if authenticate(username, password):
            print("Authentication successful.")
        else:
            print("Authentication failed.")
            sys.exit(1)
    elif command == 'change_password':
        if len(sys.argv) != 5:
            print("Usage: python client.py change_password <username> <old_password> <new_password>")
            sys.exit(1)
        username = sys.argv[2]
        old_password = sys.argv[3]
        new_password = sys.argv[4]
        if change_password(username, old_password, new_password):
            print("Password changed successfully.")
        else:
            print("Password change failed.")
            sys.exit(1)
    else:
        print("Unknown command:", command)
        sys.exit(1)
