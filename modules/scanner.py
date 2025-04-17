import nmap
import socket
from datetime import datetime

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
    
    def full_scan(self):
        """Comprehensive network scan with error handling"""
        try:
            target = socket.gethostbyname(socket.gethostname())
            self.nm.scan(hosts=target, arguments='-sS -T4 -F')
            
            return {
                'target_ip': target,
                'open_ports': list(self.nm[target]['tcp'].keys()),
                'scan_time': str(datetime.now())
            }
        except Exception as e:
            return {'error': f"Nmap scan failed: {str(e)}"}
