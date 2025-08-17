#!/usr/bin/env python3
"""
Demo script for AI Bug Bounty Reconnaissance Tool
This script demonstrates the tool's capabilities with a sample analysis
"""

import sys
import os
from datetime import datetime

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from utils import display_banner, print_status, display_results_table
from recon import ReconnaissanceEngine
from ai_analysis import AIAnalyzer

def run_demo():
    """Run a demonstration of the tool's capabilities"""
    
    # Display banner
    display_banner()
    
    print_status("Starting AI Bug Bounty Reconnaissance Tool Demo", "info")
    print_status("This demo will show you what the tool can do", "info")
    
    # Sample target for demonstration
    demo_target = "example.com"
    print_status(f"Demo target: {demo_target}", "info")
    
    print_status("\n=== DEMO MODE ===", "info")
    print_status("Note: This is a demonstration with limited functionality", "warning")
    print_status("For full functionality, set up your API keys and run: python run.py example.com", "info")
    
    try:
        # Initialize reconnaissance engine
        print_status("Initializing reconnaissance engine...", "info")
        recon_engine = ReconnaissanceEngine()
        
        # Run basic reconnaissance (without external APIs)
        print_status("Running basic reconnaissance...", "info")
        
        # Simulate some basic findings for demo purposes
        demo_recon_data = {
            'target': demo_target,
            'timestamp': datetime.now().isoformat(),
            'dns_info': {
                'domain': demo_target,
                'a_records': ['93.184.216.34'],
                'aaaa_records': ['2606:2800:220:1:248:1893:25c8:1946'],
                'mx_records': ['mail.example.com'],
                'ns_records': ['a.iana-servers.net', 'b.iana-servers.net'],
                'txt_records': ['v=spf1 -all'],
                'cname_records': []
            },
            'whois_info': {
                'registrar': 'IANA',
                'creation_date': '1995-08-14T04:00:00Z',
                'expiration_date': '2026-08-13T04:00:00Z',
                'status': ['clientTransferProhibited'],
                'name_servers': ['a.iana-servers.net', 'b.iana-servers.net']
            },
            'ssl_info': {
                'issuer': {'C': 'US', 'O': 'DigiCert Inc', 'OU': 'www.digicert.com'},
                'not_after': 'Dec 12 23:59:59 2024 GMT',
                'san': ['example.com', 'www.example.com']
            },
            'http_info': {
                'status_code': 200,
                'server': 'ECS (nyb/1D16)',
                'technologies': ['HTML5', 'CSS3'],
                'headers': {
                    'Server': 'ECS (nyb/1D16)',
                    'Content-Type': 'text/html; charset=UTF-8'
                }
            },
            'subdomains': ['www', 'mail', 'ftp'],
            'shodan_info': {},
            'censys_info': {}
        }
        
        # Initialize AI analyzer
        print_status("Initializing AI analyzer...", "info")
        ai_analyzer = AIAnalyzer()
        
        # Run AI analysis
        print_status("Running AI-powered vulnerability analysis...", "info")
        ai_analysis = ai_analyzer.analyze_vulnerabilities(demo_recon_data)
        
        # Display results
        print_status("\n=== DEMO RESULTS ===", "info")
        
        # Basic summary
        print_status(f"Target: {demo_target}", "info")
        print_status(f"Priority Score: {ai_analysis.get('priority_score', 0)}/10", "info")
        
        # DNS Records
        dns_data = []
        for record in demo_recon_data['dns_info']['a_records']:
            dns_data.append({'Type': 'A', 'Value': record})
        for record in demo_recon_data['dns_info']['mx_records']:
            dns_data.append({'Type': 'MX', 'Value': record})
        
        if dns_data:
            display_results_table("DNS Records", dns_data, ['Type', 'Value'])
        
        # Subdomains
        subdomain_data = [{'Subdomain': sub} for sub in demo_recon_data['subdomains']]
        display_results_table("Discovered Subdomains", subdomain_data, ['Subdomain'])
        
        # Technologies
        tech_data = [{'Technology': tech} for tech in demo_recon_data['http_info']['technologies']]
        display_results_table("Detected Technologies", tech_data, ['Technology'])
        
        # Vulnerabilities
        if ai_analysis.get('critical_vulnerabilities'):
            vuln_data = [{'Vulnerability': vuln} for vuln in ai_analysis['critical_vulnerabilities']]
            display_results_table("Critical Vulnerabilities", vuln_data, ['Vulnerability'])
        
        if ai_analysis.get('medium_risk_findings'):
            vuln_data = [{'Finding': finding} for finding in ai_analysis['medium_risk_findings']]
            display_results_table("Medium Risk Findings", vuln_data, ['Finding'])
        
        # Recommendations
        if ai_analysis.get('recommendations'):
            rec_data = [{'Recommendation': rec} for rec in ai_analysis['recommendations']]
            display_results_table("Recommendations", rec_data, ['Recommendation'])
        
        print_status("\n=== DEMO COMPLETED ===", "success")
        print_status("This demonstrates the basic capabilities of the tool", "info")
        print_status("For full functionality with real targets:", "info")
        print_status("1. Set up your API keys in a .env file", "info")
        print_status("2. Run: python run.py your-target.com", "info")
        
    except Exception as e:
        print_status(f"Demo error: {e}", "error")
        print_status("This might be due to missing dependencies", "warning")
        print_status("Run: python test_installation.py to check your setup", "info")

if __name__ == "__main__":
    run_demo()
