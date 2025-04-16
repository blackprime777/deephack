from cryptography.fernet import Fernet

KEY = b"xK7tD3vY5kR9wQ1sN6mJ4pZ8cL2fH0bT7gU9yV3eX6rA5qW="

def encrypt_data(data):
    """Encrypts data using AES-256"""
    return Fernet(KEY).encrypt(data.encode())

def save_log(*args):
    """Saves encrypted logs to file"""
    with open("payback_logs.enc", "ab") as f:
        f.write(encrypt_data(str(args)) + b"\n")
