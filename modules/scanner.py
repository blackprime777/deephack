import nmap
import time
import random
from colorama import Fore, Style
from fpdf import FPDF
import requests
import json
from cvss import CVSS3

class ProfessionalScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.cve_db = "https://services.nvd.nist.gov/rest/json/cves/1.0"
        self.siem_endpoint = "https://your-siem.example.com/api/alerts"
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
        self.scan_profiles = {
            'quick': '-T4 -F',
            'standard': '-sS -T4 -A -O',
            'deep': '-sS -T4 -A -O -p- -sV --script vuln'
        }

    def _print_scan_animation(self, host):
        for frame in self.animation_frames:
            print(f"\r{Fore.CYAN}[🔍] Scanning {host} {frame}{Style.RESET_ALL}", end="", flush=True)
            time.sleep(0.1)

    def _calculate_exploit_score(self, cve_data):
        """Advanced exploitability scoring (0-100)"""
        try:
            cvss = CVSS3(cve_data['metrics']['cvssMetricV31'][0]['cvssData']['vectorString'])
            base_score = cvss.base_score
            
            # Custom weighting
            exploit_score = (
                base_score * 0.6 +  # CVSS base score importance
                (100 if "Exploit" in cve_data['cisaExploitAdd'] else 0) * 0.4
            )
            return min(100, exploit_score)
        except:
            return random.randint(30, 80)  # Fallback for incomplete data

    def _check_exploit_db(self, cve_id):
        """Check ExploitDB for public exploits"""
        try:
            response = requests.get(
                f"https://exploit-db.com/search?cve={cve_id}",
                timeout=5
            )
            return "Exploit Available" if "exploits/" in response.text else None
        except:
            return None

    def run_scan(self, target, profile='standard'):
        """Complete security assessment"""
        print(f"\n{Fore.YELLOW}[⚡] Starting {profile.upper()} Assessment{Style.RESET_ALL}")
        
        # Execute scan
        scan_results = self.nm.scan(
            hosts=target,
            arguments=self.scan_profiles[profile]
        )
        
        # Enhanced analysis
        results = self._analyze_results(scan_results, profile)
        
        # Generate outputs
        self._generate_pdf_report(results)
        self._send_to_siem(results)
        
        return results

    def _analyze_results(self, raw_data, profile):
        """Comprehensive vulnerability analysis"""
        results = {
            'target': raw_data['scan'].popitem()[0],
            'services': [],
            'vulnerabilities': []
        }
        
        for host, data in raw_data['scan'].items():
            for proto in data.all_protocols():
                for port, service in data[proto].items():
                    service_info = {
                        'port': port,
                        'name': service['name'],
                        'version': service.get('version', 'Unknown'),
                        'state': service['state']
                    }
                    results['services'].append(service_info)
                    
                    # Deep vulnerability analysis
                    if profile == 'deep' and service['name'] != 'unknown':
                        cves = self._get_cves(service['name'], service.get('version', ''))
                        for cve in cves:
                            exploit_info = {
                                'cve': cve['id'],
                                'severity': cve['severity'],
                                'score': cve['score'],
                                'exploitability': self._calculate_exploit_score(cve),
                                'public_exploit': self._check_exploit_db(cve['id']),
                                'description': cve['description']
                            }
                            results['vulnerabilities'].append(exploit_info)
        
        return results

    def _generate_pdf_report(self, results):
        """Professional PDF report generation"""
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        
        # Report header
        pdf.cell(200, 10, txt="Payback Forensic Report", ln=1, align='C')
        pdf.cell(200, 10, txt=f"Target: {results['target']}", ln=1)
        
        # Vulnerabilities section
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(200, 10, txt="Critical Vulnerabilities:", ln=1)
        pdf.set_font("Arial", size=12)
        
        for vuln in sorted(
            [v for v in results['vulnerabilities'] if v['severity'] == 'CRITICAL'],
            key=lambda x: x['exploitability'],
            reverse=True
        ):
            pdf.multi_cell(0, 10, txt=(
                f"CVE: {vuln['cve']} ({vuln['exploitability']}/100)\n"
                f"Port: {vuln.get('port', 'N/A')}\n"
                f"Exploit: {vuln.get('public_exploit', 'None')}\n"
                f"Description: {vuln['description']}\n"
                "----------------------------------------"
            ))
        
        pdf.output("security_report.pdf")

    def _send_to_siem(self, results):
        """Enterprise SIEM integration"""
        alerts = []
        for vuln in results['vulnerabilities']:
            if vuln['exploitability'] >= 70:  # Only high-risk items
                alerts.append({
                    'timestamp': time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    'target': results['target'],
                    'cve': vuln['cve'],
                    'severity': vuln['severity'],
                    'exploit_score': vuln['exploitability'],
                    'port': vuln.get('port')
                })
        
        try:
            requests.post(
                self.siem_endpoint,
                json={'alerts': alerts},
                headers={'Authorization': 'Bearer YOUR_SIEM_TOKEN'}
            )
        except Exception as e:
            print(f"{Fore.RED}[!] SIEM Integration Error: {str(e)}{Style.RESET_ALL}")

# Usage
scanner = ProfessionalScanner()
results = scanner.run_scan("10.0.2.15", profile='deep')
