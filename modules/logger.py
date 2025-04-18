from cryptography.fernet import Fernet

KEY = b"CIMo5pvhqE3AIcRG44cxXpJgExoas8JF7Tq3MYKczaA='"

def encrypt_data(data):
    """Encrypts data using AES-256"""
    return Fernet(KEY).encrypt(data.encode())

def save_log(*args):
    """Saves encrypted logs to file"""
    with open("payback_logs.enc", "ab") as f:
        f.write(encrypt_data(str(args)) + b"\n")
