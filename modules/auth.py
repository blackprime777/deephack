from getpass import getpass

def verify_credentials(auth_key):
    """Secure two-factor authentication"""
    name = input("[?] Operator Name: ")
    return getpass("[?] Authentication Key: ") == auth_key
