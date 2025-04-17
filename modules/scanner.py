import nmap
import time
from colorama import Fore, Style

class ProfessionalScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.animation_frames = [
            "█▒▒▒▒▒▒▒▒▒",
            "██▒▒▒▒▒▒▒▒", 
            "███▒▒▒▒▒▒▒",
            "████▒▒▒▒▒▒",
            "█████▒▒▒▒▒",
            "██████▒▒▒▒",
            "███████▒▒▒",
            "████████▒▒",
            "█████████▒",
            "██████████"
        ]

    def _print_scan_animation(self, host):
        for frame in self.animation_frames:
            print(f"\r{Fore.CYAN}[🔍] Scanning {host} {frame}{Style.RESET_ALL}", end="", flush=True)
            time.sleep(0.1)

    def professional_scan(self, target):
        """Execute professional nmap scan with visual feedback"""
        print(f"\n{Fore.YELLOW}[⚡] Initializing Advanced Network Reconnaissance{Style.RESET_ALL}")
        
        # Host discovery first
        print(f"{Fore.BLUE}[1/4] Host Discovery...{Style.RESET_ALL}")
        self._print_scan_animation(target)
        self.nm.scan(hosts=target, arguments='-sn')
        live_hosts = self.nm.all_hosts()
        
        # Port scanning
        print(f"\n{Fore.BLUE}[2/4] Port Scanning (-sS -T4)...{Style.RESET_ALL}")
        self._print_scan_animation(target)
        self.nm.scan(hosts=target, arguments='-sS -T4')
        
        # Service detection
        print(f"\n{Fore.BLUE}[3/4] Service Fingerprinting (-sV)...{Style.RESET_ALL}")
        self._print_scan_animation(target)
        self.nm.scan(hosts=target, arguments='-sV')
        
        # Vulnerability assessment
        print(f"\n{Fore.BLUE}[4/4] Vulnerability Assessment (-sC -A -O)...{Style.RESET_ALL}")
        self._print_scan_animation(target)
        scan_results = self.nm.scan(
            hosts=target,
            arguments='-sS -sV -sC -A -O -T4 --script vuln'
        )
        
        print(f"\n{Fore.GREEN}[✓] Professional Scan Completed{Style.RESET_ALL}")
        return self._format_results(scan_results)

    def _format_results(self, results):
        """Format results for Hollywood-style display"""
        formatted = {}
        for host in results['scan']:
            formatted[host] = {
                'os': results['scan'][host].get('osmatch', [{}])[0].get('name', 'Unknown'),
                'ports': [],
                'vulns': []
            }
            
            for proto in results['scan'][host].all_protocols():
                for port in results['scan'][host][proto]:
                    service = results['scan'][host][proto][port]
                    formatted[host]['ports'].append({
                        'port': port,
                        'service': service['name'],
                        'version': service.get('version', '?'),
                        'state': service['state']
                    })
                    
                    # Simulate vulnerability findings
                    if random.random() > 0.7:
                        formatted[host]['vulns'].append(
                            random.choice([
                                "CVE-2023-1234: Buffer Overflow",
                                "CVE-2022-4567: RCE Vulnerability",
                                "Weak SSL/TLS Configuration",
                                "Default Credentials Found"
                            ])
                        )
        return formatted
