import nmap
import time
import random
from colorama import Fore, Style
from fpdf import FPDF
import requests
from cvss import CVSS3
import warnings

# Disable PDF font warnings
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
                return min(100, cve_item['metrics']['cvssMetricV2'][0]['cv_
