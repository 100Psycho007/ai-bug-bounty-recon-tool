#!/usr/bin/env python3
"""
AI Recon - Bug Bounty Reconnaissance CLI Tool
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Add modules to path
sys.path.append(str(Path(__file__).parent / "modules"))

from modules.subdomains import SubdomainEnumerator
from modules.ports import PortScanner
from modules.vulns import VulnerabilityLookup
from modules.ai_summary import AISummarizer

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="AI Recon - Automated Bug Bounty Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -d example.com
  python main.py -l domains.txt
  python main.py -d example.com -o custom_report.json
  python main.py -l domains.txt --output batch_scan.json
        """
    )
    
    # Input options (mutually exclusive)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '-d', '--domain',
        help='Single domain to scan'
    )
    group.add_argument(
        '-l', '--list',
        help='File containing list of domains (one per line)'
    )
    
    # Output options
    parser.add_argument(
        '-o', '--output',
        help='Output filename (default: target-TIMESTAMP.json)'
    )
    
    # Scan options
    parser.add_argument(
        '--no-subdomains',
        action='store_true',
        help='Skip subdomain enumeration'
    )
    parser.add_argument(
        '--no-ports',
        action='store_true',
        help='Skip port scanning'
    )
    parser.add_argument(
        '--no-vulns',
        action='store_true',
        help='Skip vulnerability lookup'
    )
    parser.add_argument(
        '--no-ai',
        action='store_true',
        help='Skip AI summary generation'
    )
    
    return parser.parse_args()

def load_domains_from_file(filename):
    """Load domains from a text file"""
    try:
        with open(filename, 'r') as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return domains
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file '{filename}': {e}")
        sys.exit(1)

def generate_output_filename(target, custom_name=None):
    """Generate output filename"""
    if custom_name:
        if not custom_name.endswith('.json'):
            custom_name += '.json'
        return custom_name
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace('.', '_').replace(':', '_')
    return f"{safe_target}-{timestamp}.json"

def scan_single_domain(domain, args):
    """Perform reconnaissance on a single domain"""
    from rich.console import Console
    from rich.panel import Panel
    
    console = Console()
    
    console.print(Panel(f"[bold blue]Starting reconnaissance on: {domain}[/bold blue]"))
    
    # Initialize modules
    subdomain_enum = SubdomainEnumerator()
    port_scanner = PortScanner()
    vuln_lookup = VulnerabilityLookup()
    ai_summarizer = AISummarizer()
    
    # Initialize results
    results = {
        "target": domain,
        "scan_date": datetime.now().isoformat() + "Z",
        "subdomains": [],
        "open_ports": [],
        "vulnerabilities": [],
        "ai_summary": ""
    }
    
    # Subdomain enumeration
    if not args.no_subdomains:
        console.print("[yellow]🔍 Enumerating subdomains...[/yellow]")
        try:
            results["subdomains"] = subdomain_enum.enumerate(domain)
            console.print(f"[green]✓ Found {len(results['subdomains'])} subdomains[/green]")
        except Exception as e:
            console.print(f"[red]✗ Subdomain enumeration failed: {e}[/red]")
            results["subdomains"] = []
    else:
        console.print("[dim]⏭️  Skipping subdomain enumeration[/dim]")
    
    # Port scanning
    if not args.no_ports:
        console.print("[yellow]🔍 Scanning ports...[/yellow]")
        try:
            results["open_ports"] = port_scanner.scan_ports(domain)
            console.print(f"[green]✓ Found {len(results['open_ports'])} open ports[/green]")
        except Exception as e:
            console.print(f"[red]✗ Port scanning failed: {e}[/red]")
            results["open_ports"] = []
    else:
        console.print("[dim]⏭️  Skipping port scanning[/dim]")
    
    # Vulnerability lookup
    if not args.no_vulns:
        console.print("[yellow]🔍 Looking up vulnerabilities...[/yellow]")
        try:
            results["vulnerabilities"] = vuln_lookup.lookup_vulnerabilities(domain, results["open_ports"])
            console.print(f"[green]✓ Found {len(results['vulnerabilities'])} potential vulnerabilities[/green]")
        except Exception as e:
            console.print(f"[red]✗ Vulnerability lookup failed: {e}[/red]")
            results["vulnerabilities"] = []
    else:
        console.print("[dim]⏭️  Skipping vulnerability lookup[/dim]")
    
    # AI summary
    if not args.no_ai:
        console.print("[yellow]🤖 Generating AI summary...[/yellow]")
        try:
            results["ai_summary"] = ai_summarizer.generate_summary(results)
            console.print("[green]✓ AI summary generated[/green]")
        except Exception as e:
            console.print(f"[red]✗ AI summary failed: {e}[/red]")
            results["ai_summary"] = ""
    else:
        console.print("[dim]⏭️  Skipping AI summary[/dim]")
    
    return results

def save_results(results, output_filename):
    """Save results to JSON file"""
    try:
        # Ensure reports directory exists
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        
        output_path = reports_dir / output_filename
        
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        return str(output_path)
    except Exception as e:
        print(f"Error saving results: {e}")
        return None

def main():
    """Main function"""
    args = parse_arguments()
    
    # Load domains
    if args.domain:
        domains = [args.domain]
    else:
        domains = load_domains_from_file(args.list)
    
    if not domains:
        print("Error: No domains to scan")
        sys.exit(1)
    
    # Process each domain
    for i, domain in enumerate(domains, 1):
        print(f"\n{'='*60}")
        print(f"Scanning domain {i}/{len(domains)}: {domain}")
        print(f"{'='*60}")
        
        # Perform reconnaissance
        results = scan_single_domain(domain, args)
        
        # Generate output filename
        output_filename = generate_output_filename(domain, args.output)
        
        # Save results
        output_path = save_results(results, output_filename)
        
        if output_path:
            print(f"\n[green]✓ Results saved to: {output_path}[/green]")
        else:
            print(f"\n[red]✗ Failed to save results[/red]")
        
        # Add separator between domains
        if i < len(domains):
            print("\n" + "="*60)
    
    print(f"\n[bold green]🎉 Reconnaissance completed for {len(domains)} domain(s)![/bold green]")

if __name__ == "__main__":
    main()
