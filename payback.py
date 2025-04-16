#!/usr/bin/env python3
import os
import sys
import time
import base64
import random
import requests
import pwd
from getpass import getpass
from cryptography.fernet import Fernet
from bs4 import BeautifulSoup

# ===== CONFIGURATION =====
AUTH_KEY = "ETH@admin/payback"
WA_LINK = "https://wa.link/s0uj6k"
ENCRYPTION_KEY = b"xK7tD3vY5kR9wQ1sN6mJ4pZ8cL2fH0bT7gU9yV3eX6rA5qW="
TOKENS = [f"{i}.{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8))}" for i in range(1, 701)]
ENCODED_TOKENS = base64.b64encode("\n".join(TOKENS).encode()).decode()

# ===== PRIVILEGE MANAGEMENT =====
def require_root():
    if os.getuid() != 0 and "--no-root" not in sys.argv:
        print("\n[!] Restarting with sudo for nmap...")
        os.execvp('sudo', ['sudo', sys.executable] + sys.argv + ["--no-root"])

def drop_privileges():
    if os.getuid() == 0:
        nobody = pwd.getpwnam("nobody")
        os.setgid(nobody.pw_gid)
        os.setuid(nobody.pw_uid)
        print("[+] Security: Running as unprivileged user")

# ===== CORE FUNCTIONALITY =====
def verify_social_media(url):
    try:
        if "instagram.com" in url:
            from instaloader import Instaloader
            L = Instaloader()
            profile = L.check_profile_id(url.split("/")[-2])
            return not profile.is_private
        return requests.get(url, timeout=10).status_code == 200
    except:
        return False

def scan_network():
    require_root()
    try:
        import nmap
        nm = nmap.PortScanner()
        ip = requests.get("https://api.ipify.org", timeout=10).text
        print(f"[*] Scanning {ip}...")
        nm.scan(hosts=ip, arguments='-F')
        
        scan_results = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    scan_results.append(f"{proto}/{port}: {nm[host][proto][port]['state']}")
        
        return "\n".join(scan_results) if scan_results else "No open ports found"
    except Exception as e:
        return f"Scan failed: {str(e)}"
    finally:
        drop_privileges()

def fake_brute_force():
    duration = 30 if "--test" in sys.argv else 1800
    print(f"[!] Bruteforcing wallet (ETA: {duration//60} minutes)...")
    for i in range(duration):
        time.sleep(1)
        if random.random() < 0.03:
            print(f"[!] Error 0x{i:04X}: Retrying...")
        print(f"\rProgress: [{'#'*(i//60)}{' '*(30-i//60)}] {i/60:.1f}/30min", end="")
    print("\n[+] Wallet compromised. Private key extracted.")

# ===== MAIN EXECUTION =====
def main():
    print(r"""
  ____
 /    \
|  ◉ ◉ |   WELCOME TO THE INSIDE
|  ▽  |   Unauthorized access = Immediate termination
 \____/    [ADMIN MONITORING ACTIVE]
    """)

    # Authentication
    name = input("[?] Full Name: ")
    if getpass("[?] Auth Key: ") != AUTH_KEY:
        exit("[!] Invalid key. Session reported.")

    print(r"""
    / _ \
  \_\(_)/_/
   _//"\\_ 
    /   \
    """)

    url = input("[?] Social Media URL: ")
    if not verify_social_media(url):
        exit("[!] Profile invalid. Logged.")

    email = input("[?] Email: ")
    if not "@" in email or len(getpass("[?] Password: ")) < 6:
        exit("[!] Credentials failed. Session terminated.")

    # Network Scan
    print("[*] Scanning network...")
    scan_data = scan_network()
    print("\n[+] Scan Results:")
    print("-" * 40)
    print(scan_data)
    print("-" * 40)

    # Wallet Process
    if input("[?] Target wallet address: ") and input("[?] Amount: $"):
        fake_brute_force()
        print(f"\n[+] PRIVATE KEY:\n{ENCODED_TOKENS}")
        
        # Encrypted Logging
        fernet = Fernet(ENCRYPTION_KEY)
        with open("payback_logs.enc", "ab") as f:
            log_data = f"{name}|{email}|{url}|{scan_data}"
            f.write(fernet.encrypt(log_data.encode()) + b"\n")
        
        # Admin Contact
        input("\n[!] Press Enter to contact Payback Admin...")
        os.system(f"xdg-open {wa.link/s0uj6k")

if __name__ == "__main__":
    main()
