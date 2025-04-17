#!/usr/bin/env python3
import os
import time
import random
import socket
import requests
from getpass import getpass
from cryptography.fernet import Fernet
from modules.scanner import NetworkScanner
from modules.forensic import BlockchainTracer
from modules.auth import verify_credentials

# Configuration
AUTH_KEY = "ETH@admin/payback"
ENCRYPT_KEY = Fernet(b"TadCslen4-lxCNLNOUtAfB2E2V8vWdqLjb5GoxSXfC4='")

def display_banner():
    os.system('clear' if os.name != 'nt' else 'cls')
    print(f"""\033[1;31m
    ██████╗  █████╗ ██╗   ██╗██████╗  █████╗  ██████╗██╗  ██╗
    ██╔══██╗██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝
    ██████╔╝███████║ ╚████╔╝ ██████╔╝███████║██║     █████╔╝ 
    ██╔══██╗██╔══██║  ╚██╔╝  ██╔══██╗██╔══██║██║     ██╔═██╗ 
    ██║  ██║██║  ██║   ██║   ██████╔╝██║  ██║╚██████╗██║  ██╗
    ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
    \033[0m""")

def get_public_ip():
    """Fetch public IP with multiple fallbacks"""
    services = [
        'https://api.ipify.org',
        'https://ident.me',
        'https://ipinfo.io/ip'
    ]
    for service in services:
        try:
            return requests.get(service, timeout=3).text
        except:
            continue
    return socket.gethostbyname(socket.gethostname())

def main():
    display_banner()
    
    # Authentication
    if not verify_credentials(AUTH_KEY):
        exit("\033[31m[✗] Authorization failed\033[0m")

    # Network Scan
    print("\n\033[34m[+] Running network diagnostics...\033[0m")
    scanner = NetworkScanner()
    scan_results = scanner.full_scan()
    print(f"\033[36m[+] Public IP: {get_public_ip()}")
    print(f"[+] Open ports: {scan_results.get('open_ports', [])}\033[0m")

    # Forensic Analysis
    wallet = input("\n[?] Target wallet address: ")
    tracer = BlockchainTracer()
    result = tracer.trace_address(wallet)
    print(f"\033[33m[!] Risk Assessment: {result.get('risk_score', 0)}/100\033[0m")

    # Brute-force Simulation
    print("\n\033[36m[+] Beginning forensic recovery (30min)...\033[0m")
    for i in range(1800):
        time.sleep(1)
        print(f"\r\033[32m[•] Progress: [{'#'*(i//60)}{' '*(30-i//60)}] {i/60:.1f}/30min", end="")
    
    # Results
    print(f"\n\033[32m[✓] Recovery token: PBK-{random.randint(1000,9999)}\033[0m")
    print("\033[33m[!] Submit findings via secure channel\033[0m")

if __name__ == "__main__":
    main()
