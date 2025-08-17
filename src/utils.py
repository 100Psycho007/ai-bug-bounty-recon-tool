"""
Utility functions for AI Bug Bounty Reconnaissance Tool
"""

import os
import json
import time
import random
from typing import Dict, List, Any, Optional
from datetime import datetime
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
import colorama
from colorama import Fore, Style

# Initialize colorama for Windows compatibility
colorama.init()

console = Console()

def load_config() -> Dict[str, Any]:
    """Load configuration from environment variables or config file"""
    config = {
        'openai_api_key': os.getenv('OPENAI_API_KEY'),
        'shodan_api_key': os.getenv('SHODAN_API_KEY'),
        'censys_api_id': os.getenv('CENSYS_API_ID'),
        'censys_api_secret': os.getenv('CENSYS_API_SECRET'),
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    if not config['openai_api_key']:
        console.print("[red]Warning: OPENAI_API_KEY not found in environment variables[/red]")
    
    return config

def save_report(target: str, data: Dict[str, Any], report_type: str = "recon") -> str:
    """Save reconnaissance data to a JSON report file"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/{target}_{report_type}_{timestamp}.json"
    
    os.makedirs("reports", exist_ok=True)
    
    report_data = {
        'target': target,
        'timestamp': timestamp,
        'report_type': report_type,
        'data': data
    }
    
    with open(filename, 'w') as f:
        json.dump(report_data, f, indent=2)
    
    return filename

def display_banner():
    """Display the tool banner"""
    banner_text = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                    AI BUG BOUNTY RECON                      ║
    ║                 Automated Reconnaissance Tool               ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    console.print(Panel(banner_text, style="bold blue"))

def display_results_table(title: str, data: List[Dict[str, Any]], columns: List[str]):
    """Display results in a formatted table"""
    table = Table(title=title, show_header=True, header_style="bold magenta")
    
    for column in columns:
        table.add_column(column, style="cyan")
    
    for row in data:
        table.add_row(*[str(row.get(col, '')) for col in columns])
    
    console.print(table)

def rate_limit_delay(min_delay: float = 1.0, max_delay: float = 3.0):
    """Add random delay to avoid rate limiting"""
    delay = random.uniform(min_delay, max_delay)
    time.sleep(delay)

def make_request(url: str, headers: Optional[Dict[str, str]] = None, timeout: int = 10) -> Optional[requests.Response]:
    """Make HTTP request with error handling and rate limiting"""
    if headers is None:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
    
    try:
        rate_limit_delay()
        response = requests.get(url, headers=headers, timeout=timeout)
        return response
    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error making request to {url}: {e}[/red]")
        return None

def validate_domain(domain: str) -> bool:
    """Validate domain format"""
    import re
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(domain_pattern, domain))

def validate_ip(ip: str) -> bool:
    """Validate IP address format"""
    import re
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return bool(re.match(ip_pattern, ip))

def print_status(message: str, status: str = "info"):
    """Print status message with color coding"""
    if status == "success":
        console.print(f"[green]✓ {message}[/green]")
    elif status == "error":
        console.print(f"[red]✗ {message}[/red]")
    elif status == "warning":
        console.print(f"[yellow]⚠ {message}[/yellow]")
    else:
        console.print(f"[blue]ℹ {message}[/blue]")

def format_size(size_bytes: int) -> str:
    """Format bytes to human readable format"""
    if size_bytes == 0:
        return "0B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.1f}{size_names[i]}"
