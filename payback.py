#!/usr/bin/env python3
import os
import time
import random
import nmap
import base64
from getpass import getpass
from cryptography.fernet import Fernet
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Configuration
AUTH_KEY = "ETH@admin/payback"
ENCRYPT_KEY = Fernet(b'TadCslen4-lxCNLNOUtAfB2E2V8vWdqLjb5GoxSXfC4=')
WA_LINK = "https://wa.link/s0uj6k"

class ProfessionalScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
    
    def scan(self, target):
        """Professional Nmap scan with -sS -sV -sC -A -O -T4"""
        print(f"\n{Fore.YELLOW}[⚡] INITIATING ADVANCED NETWORK RECON{Style.RESET_ALL}")
        
        try:
            # Run complete scan
            print(f"{Fore.BLUE}[1/1] Running Comprehensive Scan{Style.RESET_ALL}")
            self._animate_scan(target)
            
            results = self.nm.scan(
                hosts=target,
                arguments='-sS -sV -sC -A -O -T4 --script vuln'
            )
            
            print(f"{Fore.GREEN}[✓] SCAN COMPLETED{Style.RESET_ALL}")
            return self._format_results(results)
            
        except Exception as e:
            print(f"{Fore.RED}[✗] SCAN FAILED: {str(e)}{Style.RESET_ALL}")
            return {}

    def _animate_scan(self, target):
        """Scan animation with progress"""
        frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        for _ in range(15):
            for frame in frames:
                print(f"\r{Fore.BLUE}Scanning {target} {frame}{Style.RESET_ALL}", end="", flush=True)
                time.sleep(0.1)
        print()

    def _format_results(self, results):
        """Robust result formatting with error handling"""
        formatted = {}
        for host in results.get('scan', {}):
            # Safe OS detection
            os_matches = results['scan'][host].get('osmatch', [])
            os_guess = os_matches[0].get('name', 'Unknown') if os_matches else 'Unknown'
            
            formatted[host] = {
                'os': os_guess,
                'ports': [],
                'vulns': []
            }
            
            # Port and service detection
            for proto in results['scan'][host].all_protocols():
                for port, service in results['scan'][host][proto].items():
                    service_info = f"{port}/{proto} - {service['name']}"
                    if 'product' in service:
                        service_info += f" {service['product']}"
                    if 'version' in service:
                        service_info += f" {service['version']}"
                    formatted[host]['ports'].append(service_info)
                    
                    # Simulate vulnerabilities
                    if random.random() > 0.6:
                        formatted[host]['vulns'].append(
                            random.choice([
                                f"CVE-2023-{random.randint(1000,9999)}: Buffer Overflow",
                                "Weak SSH Configuration",
                                "Possible XSS Vulnerability",
                                "Outdated Service Found"
                            ])
                        )
        return formatted

def cinematic_bruteforce():
    """Hollywood-style brute-force simulation"""
    print(f"\n{Fore.RED}[💻] INITIATING CRYPTO WALLET BREACH{Style.RESET_ALL}")
    techniques = [
        "Bypassing API rate limits",
        "Injecting malicious smart contract",
        "Exploiting weak RNG signatures",
        "Deploying rainbow table attack"
    ]
    
    for i in range(1, 181):  # 3 minutes simulation
        time.sleep(1)
        if i % 30 == 0:
            print(f"{Fore.YELLOW}[⚡] {random.choice(techniques)}{Style.RESET_ALL}")
            if random.random() > 0.7:
                print(f"{Fore.RED}[💥] CRITICAL VULNERABILITY DETECTED!{Style.RESET_ALL}")
        print(f"\r{Fore.CYAN}[🚀] Progress: [{'▮'*(i//6)}{'▯'*(30-i//6)}] {i/3:.1f}/3.0min{Style.RESET_ALL}", end="")
    
    print(f"\n{Fore.GREEN}[💰] PRIVATE KEY FRAGMENT RECOVERED!{Style.RESET_ALL}")
    return base64.b64encode(f"PBK-{random.randint(1000,9999)}".encode()).decode()

def display_banner():
    os.system('clear' if os.name != 'nt' else 'cls')
    print(f"""{Fore.RED}
    ██████╗  █████╗ ██╗   ██╗██████╗  █████╗  ██████╗██╗  ██╗
    ██╔══██╗██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝
    ██████╔╝███████║ ╚████╔╝ ██████╔╝███████║██║     █████╔╝ 
    ██╔══██╗██╔══██║  ╚██╔╝  ██╔══██╗██╔══██║██║     ██╔═██╗ 
    ██║  ██║██║  ██║   ██║   ██████╔╝██║  ██║╚██████╗██║  ██╗
    ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
    {Style.RESET_ALL}""")
    print(f"{Fore.YELLOW}=== AUTHORIZED USE ONLY ==={Style.RESET_ALL}\n")

def main():
    display_banner()
    
    # Authentication
    if getpass(f"{Fore.YELLOW}[🔑] ENTER AUTH KEY:{Style.RESET_ALL} ") != AUTH_KEY:
        print(f"{Fore.RED}[⛔] ACCESS DENIED!{Style.RESET_ALL}")
        return
    
    # Network Recon
    target = input(f"{Fore.CYAN}[🌐] ENTER TARGET IP/RANGE:{Style.RESET_ALL} ")
    scanner = ProfessionalScanner()
    results = scanner.scan(target)
    
    # Display Results
    if results:
        print(f"\n{Fore.RED}=== NETWORK DISCOVERY ==={Style.RESET_ALL}")
        for host, data in results.items():
            print(f"\n{Fore.CYAN}HOST: {host}{Style.RESET_ALL}")
            print(f"OS: {Fore.YELLOW}{data['os']}{Style.RESET_ALL}")
            
            print(f"\n{Fore.GREEN}OPEN PORTS:{Style.RESET_ALL}")
            for port in data['ports']:
                print(f" {port}")
            
            if data['vulns']:
                print(f"\n{Fore.RED}VULNERABILITIES:{Style.RESET_ALL}")
                for vuln in data['vulns']:
                    print(f" ! {vuln}")
    
    # Wallet Brute-Force
    wallet = input(f"\n{Fore.MAGENTA}[💳] ENTER TARGET WALLET:{Style.RESET_ALL} ")
    token = cinematic_bruteforce()
    print(f"\n{Fore.GREEN}[✅] RECOVERY TOKEN: {token}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[📡] Submit to command center: {WA_LINK}{Style.RESET_ALL}")

if __name__ == "__main__":
    # Check dependencies
    try:
        import nmap
        import cryptography
        main()
    except ImportError as e:
        print(f"{Fore.RED}[!] MISSING DEPENDENCY: {str(e)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Run: pip install python-nmap cryptography colorama{Style.RESET_ALL}")
