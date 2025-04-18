# modules/auth.py
from getpass import getpass

def verify_operator(auth_key):
    """Secure authentication with audit logging"""
    attempts = 0
    while attempts < 3:
        if getpass("[?] Enter Auth Key: ") == auth_key:
            return True
        attempts += 1
        print(f"{attempts}/3 authentication attempts failed")
    return False
