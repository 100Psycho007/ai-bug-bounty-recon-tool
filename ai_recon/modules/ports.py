"""
Port scanning module for AI Recon
"""

import socket
import nmap
import time
from typing import List, Dict
from rich.console import Console

class PortScanner:
    def __init__(self):
        self.console = Console()
        # Top 100 most common ports
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5900, 8080,
            20, 67, 68, 69, 123, 137, 138, 161, 162, 389, 636, 1433, 1434, 1521, 1720, 1947, 2049, 2181, 3128,
            3389, 5432, 5900, 5984, 6379, 8080, 8443, 8888, 9000, 9042, 9200, 11211, 27017, 27018, 27019, 50070,
            50075, 50090, 50091, 50095, 50096, 50097, 50098, 50099, 50100, 50101, 50102, 50103, 50104, 50105, 50106,
            50107, 50108, 50109, 50110, 50111, 50112, 50113, 50114, 50115, 50116, 50117, 50118, 50119, 50120, 50121,
            50122, 50123, 50124, 50125, 50126, 50127, 50128, 50129, 50130, 50131, 50132, 50133, 50134, 50135, 50136,
            50137, 50138, 50139, 50140, 50141, 50142, 50143, 50144, 50145, 50146, 50147, 50148, 50149, 50150
        ]
        
        # Service names for common ports
        self.service_names = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
            111: "RPC", 135: "RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 993: "IMAPS", 995: "POP3S",
            1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
            8888: "HTTP-Alt", 9000: "HTTP-Alt", 9042: "Cassandra", 9200: "Elasticsearch", 11211: "Memcached",
            27017: "MongoDB", 2181: "Zookeeper", 3128: "Squid-Proxy", 5432: "PostgreSQL", 5984: "CouchDB",
            6379: "Redis", 50070: "Hadoop-NameNode", 50075: "Hadoop-DataNode", 50090: "Hadoop-SecondaryNameNode"
        }
    
    def scan_ports(self, domain: str) -> List[int]:
        """
        Scan common ports on the target domain
        Returns a list of open port numbers
        """
        open_ports = []
        
        # Try to resolve domain to IP
        try:
            ip = socket.gethostbyname(domain)
            self.console.print(f"[dim]Resolved {domain} to {ip}[/dim]")
        except socket.gaierror:
            self.console.print(f"[red]Could not resolve domain {domain}[/red]")
            return []
        
        # Try nmap first if available
        nmap_results = self._try_nmap_scan(ip)
        if nmap_results:
            open_ports = nmap_results
            self.console.print(f"[dim]Used nmap for port scanning[/dim]")
        else:
            # Fallback to socket-based scanning
            open_ports = self._socket_scan(ip)
            self.console.print(f"[dim]Used socket-based port scanning[/dim]")
        
        return sorted(open_ports)
    
    def _try_nmap_scan(self, ip: str) -> List[int]:
        """Try to use nmap for port scanning"""
        try:
            # Initialize nmap scanner
            nm = nmap.PortScanner()
            
            # Scan top 100 ports
            port_list = ','.join(map(str, self.common_ports))
            nm.scan(ip, port_list, arguments='-sS -T4 --max-retries 2')
            
            open_ports = []
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        if nm[host][proto][port]['state'] == 'open':
                            open_ports.append(port)
            
            return open_ports
            
        except Exception as e:
            self.console.print(f"[dim]Nmap scan failed: {e}[/dim]")
            return []
    
    def _socket_scan(self, ip: str) -> List[int]:
        """Socket-based port scanning fallback"""
        open_ports = []
        
        for port in self.common_ports:
            try:
                # Create socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)  # 1 second timeout
                
                # Try to connect
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                    service_name = self.service_names.get(port, "Unknown")
                    self.console.print(f"[dim]Found open port {port} ({service_name})[/dim]")
                
                sock.close()
                
                # Small delay to be respectful
                time.sleep(0.01)
                
            except (socket.error, OSError):
                pass
        
        return open_ports
    
    def get_service_info(self, port: int) -> Dict[str, str]:
        """Get service information for a specific port"""
        service_info = {
            "port": port,
            "service": self.service_names.get(port, "Unknown"),
            "protocol": "TCP"
        }
        
        # Add additional service details
        if port == 80:
            service_info["description"] = "HTTP Web Server"
        elif port == 443:
            service_info["description"] = "HTTPS Secure Web Server"
        elif port == 22:
            service_info["description"] = "SSH Remote Access"
        elif port == 21:
            service_info["description"] = "FTP File Transfer"
        elif port == 3306:
            service_info["description"] = "MySQL Database"
        elif port == 5432:
            service_info["description"] = "PostgreSQL Database"
        elif port == 27017:
            service_info["description"] = "MongoDB Database"
        elif port == 6379:
            service_info["description"] = "Redis Cache"
        else:
            service_info["description"] = "Network Service"
        
        return service_info
    
    def scan_specific_ports(self, domain: str, ports: List[int]) -> List[int]:
        """Scan specific ports on a domain"""
        open_ports = []
        
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            return []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                
                sock.close()
                time.sleep(0.1)
                
            except (socket.error, OSError):
                pass
        
        return open_ports
