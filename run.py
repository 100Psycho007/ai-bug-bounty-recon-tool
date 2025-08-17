#!/usr/bin/env python3
"""
AI Bug Bounty Reconnaissance Tool - Main Entry Point
"""

import os
import sys
import argparse
from datetime import datetime
from dotenv import load_dotenv

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from recon import ReconnaissanceEngine
from ai_analysis import AIAnalyzer
from utils import (
    display_banner, print_status, save_report, 
    display_results_table, load_config
)

def main():
    """Main function to run the AI Bug Bounty Reconnaissance Tool"""
    
    # Load environment variables
    load_dotenv()
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="AI Bug Bounty Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py example.com
  python run.py 192.168.1.1
  python run.py example.com --output detailed
  python run.py example.com --no-ai
        """
    )
    
    parser.add_argument(
        'target',
        help='Target domain or IP address to analyze'
    )
    
    parser.add_argument(
        '--output', '-o',
        choices=['basic', 'detailed', 'full'],
        default='detailed',
        help='Output detail level (default: detailed)'
    )
    
    parser.add_argument(
        '--no-ai',
        action='store_true',
        help='Disable AI analysis (use basic analysis only)'
    )
    
    parser.add_argument(
        '--save-report',
        action='store_true',
        help='Save detailed report to file'
    )
    
    parser.add_argument(
        '--config',
        help='Path to configuration file'
    )
    
    args = parser.parse_args()
    
    # Display banner
    display_banner()
    
    # Load configuration
    config = load_config()
    
    # Validate target
    target = args.target.strip()
    if not target:
        print_status("No target specified", "error")
        sys.exit(1)
    
    print_status(f"Starting reconnaissance on target: {target}", "info")
    print_status(f"Output level: {args.output}", "info")
    print_status(f"AI analysis: {'Disabled' if args.no_ai else 'Enabled'}", "info")
    
    try:
        # Initialize reconnaissance engine
        recon_engine = ReconnaissanceEngine()
        
        # Run reconnaissance
        print_status("Phase 1: Gathering reconnaissance data", "info")
        recon_data = recon_engine.run_full_reconnaissance(target)
        
        # Initialize AI analyzer
        ai_analyzer = AIAnalyzer()
        
        # Run AI analysis
        if not args.no_ai:
            print_status("Phase 2: Running AI-powered vulnerability analysis", "info")
            ai_analysis = ai_analyzer.analyze_vulnerabilities(recon_data)
        else:
            print_status("Phase 2: Running basic vulnerability analysis", "info")
            ai_analysis = ai_analyzer.analyze_vulnerabilities(recon_data)
        
        # Generate report summary
        print_status("Phase 3: Generating comprehensive report", "info")
        report_summary = ai_analyzer.generate_report_summary(recon_data, ai_analysis)
        
        # Display results based on output level
        if args.output == 'basic':
            display_basic_results(target, ai_analysis)
        elif args.output == 'detailed':
            display_detailed_results(target, recon_data, ai_analysis)
        else:  # full
            display_full_results(target, recon_data, ai_analysis, report_summary)
        
        # Save report if requested
        if args.save_report:
            save_detailed_report(target, recon_data, ai_analysis, report_summary)
        
        # Suggest next steps
        print_status("Phase 4: Generating recommendations", "info")
        next_steps = ai_analyzer.suggest_next_steps(ai_analysis)
        
        if next_steps:
            print_status("Recommended next steps:", "info")
            for i, step in enumerate(next_steps, 1):
                print_status(f"{i}. {step}", "info")
        
        print_status("Reconnaissance and analysis completed successfully!", "success")
        
    except KeyboardInterrupt:
        print_status("\nOperation cancelled by user", "warning")
        sys.exit(1)
    except Exception as e:
        print_status(f"An error occurred: {e}", "error")
        sys.exit(1)

def display_basic_results(target: str, ai_analysis: dict):
    """Display basic results summary"""
    print_status("=== BASIC RESULTS ===", "info")
    print_status(f"Target: {target}", "info")
    print_status(f"Priority Score: {ai_analysis.get('priority_score', 0)}/10", "info")
    
    critical_count = len(ai_analysis.get('critical_vulnerabilities', []))
    medium_count = len(ai_analysis.get('medium_risk_findings', []))
    
    print_status(f"Critical Vulnerabilities: {critical_count}", "error" if critical_count > 0 else "success")
    print_status(f"Medium Risk Findings: {medium_count}", "warning" if medium_count > 0 else "success")

def display_detailed_results(target: str, recon_data: dict, ai_analysis: dict):
    """Display detailed results"""
    print_status("=== DETAILED RESULTS ===", "info")
    
    # Basic summary
    display_basic_results(target, ai_analysis)
    
    # DNS Information
    if recon_data.get('dns_info'):
        dns_data = []
        dns_info = recon_data['dns_info']
        
        if dns_info.get('a_records'):
            for record in dns_info['a_records']:
                dns_data.append({'Type': 'A', 'Value': record})
        
        if dns_info.get('mx_records'):
            for record in dns_info['mx_records']:
                dns_data.append({'Type': 'MX', 'Value': record})
        
        if dns_data:
            display_results_table("DNS Records", dns_data, ['Type', 'Value'])
    
    # Subdomains
    subdomains = recon_data.get('subdomains', [])
    if subdomains:
        subdomain_data = [{'Subdomain': sub} for sub in subdomains]
        display_results_table("Discovered Subdomains", subdomain_data, ['Subdomain'])
    
    # Vulnerabilities
    if ai_analysis.get('critical_vulnerabilities'):
        vuln_data = [{'Vulnerability': vuln} for vuln in ai_analysis['critical_vulnerabilities']]
        display_results_table("Critical Vulnerabilities", vuln_data, ['Vulnerability'])
    
    if ai_analysis.get('medium_risk_findings'):
        vuln_data = [{'Finding': finding} for finding in ai_analysis['medium_risk_findings']]
        display_results_table("Medium Risk Findings", vuln_data, ['Finding'])

def display_full_results(target: str, recon_data: dict, ai_analysis: dict, report_summary: str):
    """Display full comprehensive results"""
    print_status("=== FULL COMPREHENSIVE REPORT ===", "info")
    
    # Display the full report summary
    print(report_summary)
    
    # Display additional technical details
    if recon_data.get('http_info'):
        http_info = recon_data['http_info']
        if http_info.get('technologies'):
            tech_data = [{'Technology': tech} for tech in http_info['technologies']]
            display_results_table("Detected Technologies", tech_data, ['Technology'])
    
    if recon_data.get('shodan_info', {}).get('matches'):
        shodan_data = []
        for match in recon_data['shodan_info']['matches'][:5]:  # Show first 5
            shodan_data.append({
                'IP': match.get('ip', 'N/A'),
                'Port': match.get('port', 'N/A'),
                'Product': match.get('product', 'N/A')
            })
        display_results_table("Shodan Intelligence", shodan_data, ['IP', 'Port', 'Product'])

def save_detailed_report(target: str, recon_data: dict, ai_analysis: dict, report_summary: str):
    """Save detailed report to file"""
    try:
        # Save reconnaissance data
        recon_filename = save_report(target, recon_data, "reconnaissance")
        print_status(f"Reconnaissance data saved to: {recon_filename}", "success")
        
        # Save AI analysis
        analysis_filename = save_report(target, ai_analysis, "ai_analysis")
        print_status(f"AI analysis saved to: {analysis_filename}", "success")
        
        # Save comprehensive report
        comprehensive_data = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'reconnaissance_data': recon_data,
            'ai_analysis': ai_analysis,
            'report_summary': report_summary
        }
        
        comprehensive_filename = save_report(target, comprehensive_data, "comprehensive")
        print_status(f"Comprehensive report saved to: {comprehensive_filename}", "success")
        
    except Exception as e:
        print_status(f"Error saving report: {e}", "error")

if __name__ == "__main__":
    main()
