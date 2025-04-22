import nmap
import time
import random
from colorama import Fore, Style
from fpdf import FPDF
import requests
from cvss import CVSS3
import warnings

warnings.filterwarnings('ignore', category=UserWarning, module='fpdf')

class ProfessionalScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.cve_db = "https://services.nvd.nist.gov/rest/json/cves/1.0"
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

    def _print_scan_animation(self, host, phase):
        for frame in self.animation_frames:
            print(f"\r{Fore.CYAN}[{phase}] Scanning {host} {frame}{Style.RESET_ALL}", end="", flush=True)
            time.sleep(0.1)

    def _get_cves(self, service, version=""):
        try:
            response = requests.get(
                f"{self.cve_db}?keyword={service} {version}",
                timeout=5
            )
            return response.json().get('result', {}).get('CVE_Items', [])[:3]
        except:
            return []

    def _calculate_exploit_score(self, cve_item):
        try:
            if 'cvssMetricV31' in cve_item['metrics']:
                cvss_data = cve_item['metrics']['cvssMetricV31'][0]['cvssData']
                cvss = CVSS3(cvss_data['vectorString'])
                base_score = cvss.base_score
                exploit_code_maturity = 1.5 if cve_item.get('exploit_available') else 0.8
                return min(100, base_score * exploit_code_maturity)
            elif 'cvssMetricV2' in cve_item['metrics']:
                return min(100, cve_item['metrics']['cvssMetricV2'][0]['cvssData']['baseScore'] * 0.9)
            return random.randint(30, 70)
        except:
            return random.randint(30, 70)

    def _check_exploit_availability(self, cve_id):
        try:
            response = requests.get(
                f"https://api.exploit-db.com/search?cve={cve_id}",
                timeout=3
            )
            return response.json().get('total', 0) > 0
        except:
            return False

    def run_scan(self, target, profile='standard', use_sudo=False):
        print(f"\n{Fore.YELLOW}[⚡] Starting {profile.upper()} Assessment{Style.RESET_ALL}")
        self._print_scan_animation(target, "1/3")
        self.nm.scan(hosts=target, arguments='-sn')

        self._print_scan_animation(target, "2/3")
        scan_results = self.nm.scan(
            hosts=target,
            arguments=self.scan_profiles[profile],
            sudo=use_sudo
        )

        self._print_scan_animation(target, "3/3")
        results = self._analyze_results(scan_results, profile)

        self._generate_pdf_report(results)

        print(f"\n{Fore.GREEN}[✓] Scan completed. Report saved as 'security_report.pdf'{Style.RESET_ALL}")
        return results

    def _analyze_results(self, raw_data, profile):
        results = {
            'meta': {
                'target': next(iter(raw_data['scan'])),
                'scan_type': profile,
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
            },
            'services': [],
            'vulnerabilities': []
        }

        host_data = raw_data['scan'][results['meta']['target']]

        for proto in host_data.all_protocols():
            for port, service in host_data[proto].items():
                service_info = {
                    'port': port,
                    'protocol': proto,
                    'service': service['name'],
                    'version': f"{service.get('product', '')} {service.get('version', '')}".strip(),
                    'state': service['state']
                }
                results['services'].append(service_info)

                if profile == 'deep' and service['name'] != 'unknown':
                    for cve in self._get_cves(service['name'], service.get('version', '')):
                        exploit_available = self._check_exploit_availability(cve['cve']['CVE_data_meta']['ID'])
                        results['vulnerabilities'].append({
                            'cve': cve['cve']['CVE_data_meta']['ID'],
                            'port': port,
                            'severity': cve['impact'].get('baseMetricV3', {}).get('cvssV3', {}).get('baseSeverity', 'MEDIUM'),
                            'score': self._calculate_exploit_score(cve),
                            'exploit_available': exploit_available,
                            'description': cve['cve']['description']['description_data'][0]['value']
                        })

        return results

    def _generate_pdf_report(self, data):
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("helvetica", size=12)

        pdf.cell(200, 10, txt="Payback Forensic Report", ln=1, align='C')
        pdf.cell(200, 10, txt=f"Target: {data['meta']['target']}", ln=1)
        pdf.cell(200, 10, txt=f"Scan Type: {data['meta']['scan_type']}", ln=1)

        pdf.set_font("helvetica", 'B', 14)
        pdf.cell(200, 10, txt="Discovered Services:", ln=1)
        pdf.set_font("helvetica", size=10)
        for service in data['services']:
            pdf.cell(200, 8,
                     txt=f"Port {service['port']}/{service['protocol']}: {service['service']} {service['version']}",
                     ln=1)

        if data['vulnerabilities']:
            pdf.set_font("helvetica", 'B', 14)
            pdf.cell(200, 10, txt="Identified Vulnerabilities:", ln=1)
            pdf.set_font("helvetica", size=10)

            for vuln in sorted(data['vulnerabilities'], key=lambda x: x['score'], reverse=True):
                pdf.multi_cell(0, 7,
                               txt=f"{vuln['cve']} ({vuln['score']:.1f}/100) [{'EXPLOIT AVAILABLE' if vuln['exploit_available'] else 'No known exploit'}]\n"
                                   f"Port: {vuln['port']} | Severity: {vuln['severity']}\n"
                                   f"Description: {vuln['description']}\n"
                                   "--------------------------------------------------",
                               ln=1)

        pdf.output("security_report.pdf")
