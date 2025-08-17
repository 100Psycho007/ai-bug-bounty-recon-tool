"""
Subdomain enumeration module for AI Recon
"""

import subprocess
import requests
import socket
import time
from typing import List, Set
from rich.console import Console

class SubdomainEnumerator:
    def __init__(self):
        self.console = Console()
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test', 'staging',
            'api', 'cdn', 'static', 'img', 'images', 'media', 'support',
            'help', 'docs', 'wiki', 'forum', 'shop', 'store', 'app',
            'mobile', 'web', 'secure', 'login', 'dashboard', 'portal',
            'backup', 'db', 'database', 'smtp', 'pop', 'imap', 'ns1', 'ns2'
        ]
    
    def enumerate(self, domain: str) -> List[str]:
        """
        Enumerate subdomains using multiple methods
        Returns a list of unique subdomains
        """
        subdomains = set()
        
        # Try subfinder first
        subfinder_results = self._try_subfinder(domain)
        if subfinder_results:
            subdomains.update(subfinder_results)
            self.console.print(f"[dim]Found {len(subfinder_results)} subdomains via subfinder[/dim]")
        
        # Try crt.sh API
        crt_results = self._try_crt_sh(domain)
        if crt_results:
            subdomains.update(crt_results)
            self.console.print(f"[dim]Found {len(crt_results)} subdomains via crt.sh[/dim]")
        
        # Try common subdomain brute force
        brute_results = self._brute_force_common(domain)
        if brute_results:
            subdomains.update(brute_results)
            self.console.print(f"[dim]Found {len(brute_results)} subdomains via brute force[/dim]")
        
        # Convert to list and sort
        result_list = sorted(list(subdomains))
        
        # Remove the main domain if it's in the list
        result_list = [sub for sub in result_list if sub != domain]
        
        return result_list
    
    def _try_subfinder(self, domain: str) -> Set[str]:
        """Try to use subfinder if installed"""
        try:
            # Check if subfinder is available
            result = subprocess.run(['subfinder', '--version'], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                # Run subfinder
                cmd = ['subfinder', '-d', domain, '-silent']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                if result.returncode == 0:
                    subdomains = set()
                    for line in result.stdout.strip().split('\n'):
                        if line.strip():
                            subdomains.add(line.strip())
                    return subdomains
                    
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            pass
        
        return set()
    
    def _try_crt_sh(self, domain: str) -> Set[str]:
        """Query crt.sh for SSL certificate subdomains"""
        try:
            # Query crt.sh API
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                
                for entry in data:
                    if 'name_value' in entry:
                        names = entry['name_value'].split('\n')
                        for name in names:
                            name = name.strip()
                            if name and name.endswith(domain):
                                subdomains.add(name)
                
                return subdomains
                
        except (requests.RequestException, ValueError, KeyError):
            pass
        
        return set()
    
    def _brute_force_common(self, domain: str) -> Set[str]:
        """Brute force common subdomain names"""
        subdomains = set()
        
        for sub in self.common_subdomains:
            subdomain = f"{sub}.{domain}"
            try:
                # Try to resolve the subdomain
                socket.gethostbyname(subdomain)
                subdomains.add(subdomain)
                time.sleep(0.1)  # Small delay to be respectful
            except socket.gaierror:
                pass
        
        return subdomains
    
    def _validate_subdomain(self, subdomain: str) -> bool:
        """Validate if a subdomain is properly formatted"""
        try:
            # Basic validation
            if not subdomain or '.' not in subdomain:
                return False
            
            # Check if it resolves
            socket.gethostbyname(subdomain)
            return True
            
        except (socket.gaierror, socket.error):
            return False
