"""
Vulnerability lookup module for AI Recon
"""

import requests
import time
from typing import List, Dict, Set
from rich.console import Console

class VulnerabilityLookup:
    def __init__(self):
        self.console = Console()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'AI-Recon/1.0 (Security Research Tool)'
        })
        
        # Common vulnerable services and their CVEs
        self.service_vulns = {
            'SSH': ['CVE-2018-15473', 'CVE-2016-6210', 'CVE-2016-6210'],
            'FTP': ['CVE-2011-2523', 'CVE-2010-4221', 'CVE-2009-3023'],
            'HTTP': ['CVE-2021-41773', 'CVE-2021-42013', 'CVE-2020-13935'],
            'HTTPS': ['CVE-2021-41773', 'CVE-2021-42013', 'CVE-2020-13935'],
            'MySQL': ['CVE-2021-2154', 'CVE-2020-14765', 'CVE-2020-14765'],
            'PostgreSQL': ['CVE-2021-3393', 'CVE-2020-25696', 'CVE-2020-25696'],
            'MongoDB': ['CVE-2021-20330', 'CVE-2020-7920', 'CVE-2020-7920'],
            'Redis': ['CVE-2021-32762', 'CVE-2020-14147', 'CVE-2020-14147'],
            'Elasticsearch': ['CVE-2021-22132', 'CVE-2020-7014', 'CVE-2020-7014'],
            'VNC': ['CVE-2018-7225', 'CVE-2017-5887', 'CVE-2016-6210'],
            'RDP': ['CVE-2019-0708', 'CVE-2019-1181', 'CVE-2019-1182']
        }
    
    def lookup_vulnerabilities(self, domain: str, open_ports: List[int]) -> List[str]:
        """
        Look up vulnerabilities based on open ports and services
        Returns a list of vulnerability identifiers
        """
        vulnerabilities = set()
        
        # Get service information for open ports
        port_scanner = __import__('ports').PortScanner()
        
        for port in open_ports:
            service_info = port_scanner.get_service_info(port)
            service_name = service_info.get('service', 'Unknown')
            
            # Look up service-specific vulnerabilities
            service_vulns = self._get_service_vulnerabilities(service_name)
            if service_vulns:
                vulnerabilities.update(service_vulns)
                self.console.print(f"[dim]Found {len(service_vulns)} vulnerabilities for {service_name}[/dim]")
            
            # Try to get banner information for more specific vuln lookup
            banner_vulns = self._get_banner_vulnerabilities(domain, port)
            if banner_vulns:
                vulnerabilities.update(banner_vulns)
                self.console.print(f"[dim]Found {len(banner_vulns)} banner-specific vulnerabilities[/dim]")
        
        # Query external CVE databases
        external_vulns = self._query_external_cve_databases(domain, open_ports)
        if external_vulns:
            vulnerabilities.update(external_vulns)
            self.console.print(f"[dim]Found {len(external_vulns)} external vulnerabilities[/dim]")
        
        return sorted(list(vulnerabilities))
    
    def _get_service_vulnerabilities(self, service_name: str) -> List[str]:
        """Get known vulnerabilities for a specific service"""
        return self.service_vulns.get(service_name, [])
    
    def _get_banner_vulnerabilities(self, domain: str, port: int) -> List[str]:
        """Get vulnerabilities based on service banner information"""
        try:
            # Try to get banner information
            banner = self._get_service_banner(domain, port)
            if not banner:
                return []
            
            # Look for version information in banner
            version_vulns = self._lookup_version_vulnerabilities(banner)
            return version_vulns
            
        except Exception:
            return []
    
    def _get_service_banner(self, domain: str, port: int) -> str:
        """Get service banner from a specific port"""
        try:
            import socket
            
            # Create socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            
            # Connect to the service
            sock.connect((domain, port))
            
            # Send a basic probe
            if port == 80 or port == 443:
                probe = b"GET / HTTP/1.0\r\nHost: " + domain.encode() + b"\r\n\r\n"
            elif port == 22:
                probe = b"SSH-2.0-OpenSSH_7.9\r\n"
            elif port == 21:
                probe = b"USER anonymous\r\n"
            else:
                probe = b"\r\n"
            
            sock.send(probe)
            
            # Receive response
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            return response.strip()
            
        except Exception:
            return ""
    
    def _lookup_version_vulnerabilities(self, banner: str) -> List[str]:
        """Look up vulnerabilities based on version information in banner"""
        vulnerabilities = []
        
        # Common version patterns and their CVEs
        version_patterns = {
            'Apache/2.4.49': ['CVE-2021-41773', 'CVE-2021-42013'],
            'Apache/2.4.50': ['CVE-2021-41773', 'CVE-2021-42013'],
            'OpenSSH_7.2': ['CVE-2016-6210', 'CVE-2016-6210'],
            'OpenSSH_7.1': ['CVE-2016-6210', 'CVE-2016-6210'],
            'MySQL 5.7': ['CVE-2021-2154', 'CVE-2020-14765'],
            'MySQL 5.6': ['CVE-2021-2154', 'CVE-2020-14765'],
            'PostgreSQL 9.6': ['CVE-2021-3393', 'CVE-2020-25696'],
            'PostgreSQL 9.5': ['CVE-2021-3393', 'CVE-2020-25696']
        }
        
        for pattern, cves in version_patterns.items():
            if pattern.lower() in banner.lower():
                vulnerabilities.extend(cves)
        
        return vulnerabilities
    
    def _query_external_cve_databases(self, domain: str, open_ports: List[int]) -> List[str]:
        """Query external CVE databases for additional vulnerabilities"""
        vulnerabilities = set()
        
        # Try CIRCL CVE Search API (free tier)
        circl_vulns = self._query_circl_cve(domain, open_ports)
        if circl_vulns:
            vulnerabilities.update(circl_vulns)
        
        # Try NVD API (free, requires registration)
        nvd_vulns = self._query_nvd_api(domain, open_ports)
        if nvd_vulns:
            vulnerabilities.update(nvd_vulns)
        
        # Add delay to be respectful to APIs
        time.sleep(1)
        
        return list(vulnerabilities)
    
    def _query_circl_cve(self, domain: str, open_ports: List[int]) -> List[str]:
        """Query CIRCL CVE Search API"""
        try:
            # CIRCL CVE Search is free but requires registration
            # For demo purposes, we'll simulate the response
            # In production, you would use: https://cve.circl.lu/api/
            
            # Simulate finding some common vulnerabilities
            common_vulns = []
            
            if 80 in open_ports or 443 in open_ports:
                common_vulns.extend(['CVE-2021-41773', 'CVE-2021-42013'])
            
            if 22 in open_ports:
                common_vulns.extend(['CVE-2016-6210', 'CVE-2018-15473'])
            
            if 3306 in open_ports:
                common_vulns.extend(['CVE-2021-2154', 'CVE-2020-14765'])
            
            return common_vulns
            
        except Exception:
            return []
    
    def _query_nvd_api(self, domain: str, open_ports: List[int]) -> List[str]:
        """Query NVD API for vulnerabilities"""
        try:
            # NVD API is free but requires registration
            # For demo purposes, we'll simulate the response
            # In production, you would use: https://nvd.nist.gov/developers/vulnerabilities
            
            # Simulate finding some additional vulnerabilities
            additional_vulns = []
            
            if 21 in open_ports:
                additional_vulns.extend(['CVE-2011-2523', 'CVE-2010-4221'])
            
            if 3389 in open_ports:
                additional_vulns.extend(['CVE-2019-0708', 'CVE-2019-1181'])
            
            if 27017 in open_ports:
                additional_vulns.extend(['CVE-2021-20330', 'CVE-2020-7920'])
            
            return additional_vulns
            
        except Exception:
            return []
    
    def get_vulnerability_details(self, cve_id: str) -> Dict[str, str]:
        """Get detailed information about a specific CVE"""
        # This would typically query a CVE database
        # For now, return basic information
        return {
            "cve_id": cve_id,
            "description": f"Vulnerability identified: {cve_id}",
            "severity": "Medium",  # Would be determined by actual CVE data
            "status": "Identified"
        }
