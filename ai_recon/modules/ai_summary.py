"""
AI Summary module for AI Recon
"""

import os
import openai
from typing import Dict, Any
from rich.console import Console
from dotenv import load_dotenv

class AISummarizer:
    def __init__(self):
        self.console = Console()
        self.client = None
        
        # Load environment variables
        load_dotenv()
        
        # Try to initialize OpenAI client
        api_key = os.getenv('OPENAI_API_KEY')
        if api_key:
            try:
                self.client = openai.OpenAI(api_key=api_key)
                self.console.print("[dim]OpenAI API initialized[/dim]")
            except Exception as e:
                self.console.print(f"[dim]Failed to initialize OpenAI API: {e}[/dim]")
                self.client = None
        else:
            self.console.print("[dim]No OpenAI API key found[/dim]")
    
    def generate_summary(self, scan_results: Dict[str, Any]) -> str:
        """
        Generate AI summary of the reconnaissance results
        Returns a plain language summary of findings
        """
        if not self.client:
            return self._generate_basic_summary(scan_results)
        
        try:
            # Create prompt for AI analysis
            prompt = self._create_analysis_prompt(scan_results)
            
            # Get AI response
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",  # Use cheaper model for cost efficiency
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert analyzing reconnaissance results. Provide clear, actionable insights in plain language."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=500,
                temperature=0.3
            )
            
            ai_summary = response.choices[0].message.content.strip()
            return ai_summary
            
        except Exception as e:
            self.console.print(f"[dim]AI summary failed: {e}[/dim]")
            return self._generate_basic_summary(scan_results)
    
    def _create_analysis_prompt(self, scan_results: Dict[str, Any]) -> str:
        """Create a comprehensive prompt for AI analysis"""
        
        target = scan_results.get('target', 'Unknown')
        subdomains = scan_results.get('subdomains', [])
        open_ports = scan_results.get('open_ports', [])
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        prompt = f"""
        Please analyze the following reconnaissance results for {target} and provide a clear, actionable summary:

        TARGET: {target}
        SUBDOMAINS FOUND: {len(subdomains)} ({', '.join(subdomains[:5]) if subdomains else 'None'})
        OPEN PORTS: {len(open_ports)} ({', '.join(map(str, open_ports[:10])) if open_ports else 'None'})
        VULNERABILITIES IDENTIFIED: {len(vulnerabilities)} ({', '.join(vulnerabilities[:5]) if vulnerabilities else 'None'})

        Please provide:
        1. A brief overview of the target's attack surface
        2. Key security concerns based on open ports and services
        3. Specific risks from identified vulnerabilities
        4. Recommended next steps for security assessment

        Keep the summary concise, professional, and actionable. Focus on the most important findings.
        """
        
        return prompt
    
    def _generate_basic_summary(self, scan_results: Dict[str, Any]) -> str:
        """Generate a basic summary when AI is not available"""
        
        target = scan_results.get('target', 'Unknown')
        subdomains = scan_results.get('subdomains', [])
        open_ports = scan_results.get('open_ports', [])
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        summary_parts = []
        
        # Overview
        summary_parts.append(f"Reconnaissance completed for {target}.")
        
        # Subdomain findings
        if subdomains:
            summary_parts.append(f"Discovered {len(subdomains)} subdomains, expanding the attack surface.")
        else:
            summary_parts.append("No additional subdomains discovered.")
        
        # Port findings
        if open_ports:
            summary_parts.append(f"Identified {len(open_ports)} open ports, indicating active services.")
            
            # Highlight critical ports
            critical_ports = [p for p in open_ports if p in [21, 22, 23, 80, 443, 3389, 3306, 5432]]
            if critical_ports:
                summary_parts.append(f"Critical services detected on ports: {', '.join(map(str, critical_ports))}.")
        else:
            summary_parts.append("No open ports detected.")
        
        # Vulnerability findings
        if vulnerabilities:
            summary_parts.append(f"Found {len(vulnerabilities)} potential vulnerabilities requiring investigation.")
            
            # Categorize vulnerabilities
            web_vulns = [v for v in vulnerabilities if 'CVE-2021-41773' in v or 'CVE-2021-42013' in v]
            if web_vulns:
                summary_parts.append("Web server vulnerabilities detected - immediate attention required.")
            
            db_vulns = [v for v in vulnerabilities if 'CVE-2021-2154' in v or 'CVE-2020-14765' in v]
            if db_vulns:
                summary_parts.append("Database vulnerabilities identified - review access controls.")
        else:
            summary_parts.append("No specific vulnerabilities identified in this scan.")
        
        # Recommendations
        if open_ports or vulnerabilities:
            summary_parts.append("Recommend conducting detailed vulnerability assessment and penetration testing.")
        else:
            summary_parts.append("Target appears to have minimal external attack surface.")
        
        return " ".join(summary_parts)
    
    def _analyze_risk_level(self, scan_results: Dict[str, Any]) -> str:
        """Analyze the overall risk level of the findings"""
        
        risk_score = 0
        open_ports = scan_results.get('open_ports', [])
        vulnerabilities = scan_results.get('vulnerabilities', [])
        subdomains = scan_results.get('subdomains', [])
        
        # Port-based risk
        critical_ports = [21, 22, 23, 3389, 3306, 5432, 27017]  # FTP, SSH, Telnet, RDP, DBs
        for port in open_ports:
            if port in critical_ports:
                risk_score += 2
            elif port in [80, 443, 8080, 8443]:  # Web services
                risk_score += 1
        
        # Vulnerability-based risk
        risk_score += len(vulnerabilities) * 2
        
        # Subdomain-based risk
        risk_score += len(subdomains) * 0.5
        
        # Determine risk level
        if risk_score >= 10:
            return "HIGH"
        elif risk_score >= 5:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _get_service_insights(self, open_ports: list) -> list:
        """Get insights about services running on open ports"""
        insights = []
        
        service_insights = {
            21: "FTP service - check for anonymous access and weak credentials",
            22: "SSH service - review authentication methods and access controls",
            23: "Telnet service - insecure protocol, consider disabling",
            80: "HTTP service - check for security headers and vulnerabilities",
            443: "HTTPS service - verify SSL/TLS configuration",
            3306: "MySQL database - ensure proper access controls",
            5432: "PostgreSQL database - review authentication settings",
            27017: "MongoDB database - check for exposed admin interfaces",
            3389: "RDP service - verify network access controls",
            5900: "VNC service - ensure encrypted connections"
        }
        
        for port in open_ports:
            if port in service_insights:
                insights.append(f"Port {port}: {service_insights[port]}")
        
        return insights
