"""
Core reconnaissance logic for AI Bug Bounty Reconnaissance Tool
"""

import dns.resolver
import whois
import requests
import socket
import ssl
import json
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import shodan
import censys.search
from utils import (
    console, make_request, validate_domain, validate_ip, 
    print_status, rate_limit_delay, load_config
)

class ReconnaissanceEngine:
    def __init__(self):
        self.config = load_config()
        self.shodan_api = None
        self.censys_api = None
        
        # Initialize APIs if keys are available
        if self.config.get('shodan_api_key'):
            try:
                self.shodan_api = shodan.Shodan(self.config['shodan_api_key'])
                print_status("Shodan API initialized", "success")
            except Exception as e:
                print_status(f"Failed to initialize Shodan API: {e}", "error")
        
        if self.config.get('censys_api_id') and self.config.get('censys_api_secret'):
            try:
                self.censys_api = censys.search.CensysHosts(
                    api_id=self.config['censys_api_id'],
                    api_secret=self.config['censys_api_secret']
                )
                print_status("Censys API initialized", "success")
            except Exception as e:
                print_status(f"Failed to initialize Censys API: {e}", "error")

    def gather_dns_info(self, domain: str) -> Dict[str, Any]:
        """Gather DNS information for a domain"""
        print_status(f"Gathering DNS information for {domain}", "info")
        
        dns_info = {
            'domain': domain,
            'a_records': [],
            'aaaa_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'cname_records': []
        }
        
        try:
            # A records
            try:
                answers = dns.resolver.resolve(domain, 'A')
                dns_info['a_records'] = [str(rdata) for rdata in answers]
            except Exception:
                pass
            
            # AAAA records
            try:
                answers = dns.resolver.resolve(domain, 'AAAA')
                dns_info['aaaa_records'] = [str(rdata) for rdata in answers]
            except Exception:
                pass
            
            # MX records
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                dns_info['mx_records'] = [str(rdata.exchange) for rdata in answers]
            except Exception:
                pass
            
            # NS records
            try:
                answers = dns.resolver.resolve(domain, 'NS')
                dns_info['ns_records'] = [str(rdata) for rdata in answers]
            except Exception:
                pass
            
            # TXT records
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                dns_info['txt_records'] = [str(rdata) for rdata in answers]
            except Exception:
                pass
            
            # CNAME records
            try:
                answers = dns.resolver.resolve(domain, 'CNAME')
                dns_info['cname_records'] = [str(rdata) for rdata in answers]
            except Exception:
                pass
                
        except Exception as e:
            print_status(f"Error gathering DNS info: {e}", "error")
        
        return dns_info

    def gather_whois_info(self, domain: str) -> Dict[str, Any]:
        """Gather WHOIS information for a domain"""
        print_status(f"Gathering WHOIS information for {domain}", "info")
        
        whois_info = {}
        
        try:
            w = whois.whois(domain)
            whois_info = {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'updated_date': str(w.updated_date) if w.updated_date else None,
                'status': w.status,
                'name_servers': w.name_servers,
                'emails': w.emails
            }
        except Exception as e:
            print_status(f"Error gathering WHOIS info: {e}", "error")
        
        return whois_info

    def gather_ssl_info(self, domain: str) -> Dict[str, Any]:
        """Gather SSL certificate information"""
        print_status(f"Gathering SSL information for {domain}", "info")
        
        ssl_info = {}
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'san': cert.get('subjectAltName', [])
                    }
        except Exception as e:
            print_status(f"Error gathering SSL info: {e}", "error")
        
        return ssl_info

    def gather_http_info(self, domain: str) -> Dict[str, Any]:
        """Gather HTTP information and headers"""
        print_status(f"Gathering HTTP information for {domain}", "info")
        
        http_info = {}
        
        try:
            url = f"https://{domain}"
            response = make_request(url)
            
            if response:
                http_info = {
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'server': response.headers.get('Server'),
                    'x_powered_by': response.headers.get('X-Powered-By'),
                    'content_type': response.headers.get('Content-Type'),
                    'content_length': response.headers.get('Content-Length'),
                    'technologies': self._detect_technologies(response)
                }
        except Exception as e:
            print_status(f"Error gathering HTTP info: {e}", "error")
        
        return http_info

    def _detect_technologies(self, response: requests.Response) -> List[str]:
        """Detect technologies from HTTP response"""
        technologies = []
        
        # Check headers for common technology indicators
        headers = response.headers
        
        if 'X-Powered-By' in headers:
            technologies.append(headers['X-Powered-By'])
        
        if 'Server' in headers:
            technologies.append(headers['Server'])
        
        # Check for common frameworks in response body
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for React
            if soup.find('div', {'id': 'root'}) or 'react' in response.text.lower():
                technologies.append('React')
            
            # Check for Angular
            if soup.find('div', {'ng-app': True}) or 'ng-' in response.text:
                technologies.append('Angular')
            
            # Check for Vue
            if 'vue' in response.text.lower() or soup.find('div', {'id': 'app'}):
                technologies.append('Vue.js')
            
            # Check for jQuery
            if 'jquery' in response.text.lower():
                technologies.append('jQuery')
            
            # Check for Bootstrap
            if 'bootstrap' in response.text.lower():
                technologies.append('Bootstrap')
                
        except Exception:
            pass
        
        return list(set(technologies))

    def gather_subdomains(self, domain: str) -> List[str]:
        """Gather subdomains using various techniques"""
        print_status(f"Gathering subdomains for {domain}", "info")
        
        subdomains = set()
        
        # Common subdomain wordlist
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test', 'staging',
            'api', 'cdn', 'static', 'img', 'images', 'media', 'support',
            'help', 'docs', 'wiki', 'forum', 'shop', 'store', 'app'
        ]
        
        for sub in common_subdomains:
            subdomain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                subdomains.add(subdomain)
                print_status(f"Found subdomain: {subdomain}", "success")
            except socket.gaierror:
                pass
        
        return list(subdomains)

    def gather_shodan_info(self, target: str) -> Dict[str, Any]:
        """Gather information from Shodan"""
        if not self.shodan_api:
            return {}
        
        print_status(f"Gathering Shodan information for {target}", "info")
        
        shodan_info = {}
        
        try:
            # Search for the target
            results = self.shodan_api.search(target)
            
            shodan_info = {
                'total_results': results['total'],
                'matches': []
            }
            
            for match in results['matches'][:10]:  # Limit to first 10 results
                shodan_info['matches'].append({
                    'ip': match.get('ip_str'),
                    'port': match.get('port'),
                    'product': match.get('product'),
                    'version': match.get('version'),
                    'os': match.get('os'),
                    'timestamp': match.get('timestamp'),
                    'data': match.get('data', '')[:200]  # First 200 chars
                })
                
        except Exception as e:
            print_status(f"Error gathering Shodan info: {e}", "error")
        
        return shodan_info

    def gather_censys_info(self, target: str) -> Dict[str, Any]:
        """Gather information from Censys"""
        if not self.censys_api:
            return {}
        
        print_status(f"Gathering Censys information for {target}", "info")
        
        censys_info = {}
        
        try:
            # Search for the target
            query = f"hosts: {target}"
            results = list(self.censys_api.search(query, max_records=10))
            
            censys_info = {
                'total_results': len(results),
                'matches': []
            }
            
            for result in results:
                censys_info['matches'].append({
                    'ip': result.get('ip'),
                    'ports': result.get('ports', []),
                    'services': list(result.get('services', {}).keys()),
                    'location': result.get('location', {}),
                    'autonomous_system': result.get('autonomous_system', {})
                })
                
        except Exception as e:
            print_status(f"Error gathering Censys info: {e}", "error")
        
        return censys_info

    def run_full_reconnaissance(self, target: str) -> Dict[str, Any]:
        """Run full reconnaissance on a target"""
        print_status(f"Starting full reconnaissance on {target}", "info")
        
        recon_data = {
            'target': target,
            'timestamp': None,
            'dns_info': {},
            'whois_info': {},
            'ssl_info': {},
            'http_info': {},
            'subdomains': [],
            'shodan_info': {},
            'censys_info': {}
        }
        
        # Determine if target is domain or IP
        if validate_domain(target):
            recon_data['dns_info'] = self.gather_dns_info(target)
            recon_data['whois_info'] = self.gather_whois_info(target)
            recon_data['ssl_info'] = self.gather_ssl_info(target)
            recon_data['http_info'] = self.gather_http_info(target)
            recon_data['subdomains'] = self.gather_subdomains(target)
        elif validate_ip(target):
            # For IP addresses, focus on port scanning and service detection
            pass
        
        # Gather information from external APIs
        recon_data['shodan_info'] = self.gather_shodan_info(target)
        recon_data['censys_info'] = self.gather_censys_info(target)
        
        print_status(f"Reconnaissance completed for {target}", "success")
        
        return recon_data
