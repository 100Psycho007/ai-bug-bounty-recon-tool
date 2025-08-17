"""
AI analysis logic for AI Bug Bounty Reconnaissance Tool
"""

import openai
import json
from typing import Dict, List, Any, Optional
from utils import console, print_status, load_config

class AIAnalyzer:
    def __init__(self):
        self.config = load_config()
        self.client = None
        
        if self.config.get('openai_api_key'):
            try:
                self.client = openai.OpenAI(api_key=self.config['openai_api_key'])
                print_status("OpenAI API initialized", "success")
            except Exception as e:
                print_status(f"Failed to initialize OpenAI API: {e}", "error")
        else:
            print_status("OpenAI API key not found - AI analysis will be limited", "warning")

    def analyze_vulnerabilities(self, recon_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze reconnaissance data for potential vulnerabilities"""
        print_status("Starting AI-powered vulnerability analysis", "info")
        
        if not self.client:
            return self._basic_vulnerability_analysis(recon_data)
        
        try:
            # Prepare the analysis prompt
            prompt = self._create_vulnerability_analysis_prompt(recon_data)
            
            # Get AI analysis
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert specializing in bug bounty hunting and vulnerability assessment. Analyze the provided reconnaissance data and identify potential security vulnerabilities, attack vectors, and areas of interest for bug bounty hunters."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=2000,
                temperature=0.3
            )
            
            ai_analysis = response.choices[0].message.content
            
            # Parse and structure the AI response
            structured_analysis = self._parse_ai_analysis(ai_analysis)
            
            return structured_analysis
            
        except Exception as e:
            print_status(f"Error in AI analysis: {e}", "error")
            return self._basic_vulnerability_analysis(recon_data)

    def _create_vulnerability_analysis_prompt(self, recon_data: Dict[str, Any]) -> str:
        """Create a comprehensive prompt for vulnerability analysis"""
        
        prompt = f"""
        Please analyze the following reconnaissance data for potential security vulnerabilities and bug bounty opportunities:

        TARGET: {recon_data.get('target', 'Unknown')}

        DNS INFORMATION:
        - A Records: {recon_data.get('dns_info', {}).get('a_records', [])}
        - MX Records: {recon_data.get('dns_info', {}).get('mx_records', [])}
        - TXT Records: {recon_data.get('dns_info', {}).get('txt_records', [])}
        - NS Records: {recon_data.get('dns_info', {}).get('ns_records', [])}

        WHOIS INFORMATION:
        - Registrar: {recon_data.get('whois_info', {}).get('registrar', 'Unknown')}
        - Creation Date: {recon_data.get('whois_info', {}).get('creation_date', 'Unknown')}
        - Status: {recon_data.get('whois_info', {}).get('status', 'Unknown')}

        SSL CERTIFICATE:
        - Issuer: {recon_data.get('ssl_info', {}).get('issuer', {})}
        - Valid Until: {recon_data.get('ssl_info', {}).get('not_after', 'Unknown')}
        - Subject Alt Names: {recon_data.get('ssl_info', {}).get('san', [])}

        HTTP INFORMATION:
        - Server: {recon_data.get('http_info', {}).get('server', 'Unknown')}
        - Technologies: {recon_data.get('http_info', {}).get('technologies', [])}
        - Headers: {recon_data.get('http_info', {}).get('headers', {})}

        SUBDOMAINS:
        {recon_data.get('subdomains', [])}

        EXTERNAL INTEL:
        - Shodan Results: {len(recon_data.get('shodan_info', {}).get('matches', []))} matches
        - Censys Results: {len(recon_data.get('censys_info', {}).get('matches', []))} matches

        Please provide a structured analysis including:

        1. CRITICAL VULNERABILITIES: High-risk security issues that should be prioritized
        2. MEDIUM RISK FINDINGS: Moderate security concerns
        3. LOW RISK OBSERVATIONS: Minor security observations
        4. ATTACK VECTORS: Potential ways to exploit identified vulnerabilities
        5. RECOMMENDATIONS: Specific steps for bug bounty hunters
        6. PRIORITY SCORE: Overall risk assessment (1-10 scale)

        Format your response as JSON with these exact keys:
        {{
            "critical_vulnerabilities": [],
            "medium_risk_findings": [],
            "low_risk_observations": [],
            "attack_vectors": [],
            "recommendations": [],
            "priority_score": 0,
            "summary": ""
        }}
        """
        
        return prompt

    def _parse_ai_analysis(self, ai_response: str) -> Dict[str, Any]:
        """Parse and structure the AI response"""
        try:
            # Try to extract JSON from the response
            start_idx = ai_response.find('{')
            end_idx = ai_response.rfind('}') + 1
            
            if start_idx != -1 and end_idx != 0:
                json_str = ai_response[start_idx:end_idx]
                analysis = json.loads(json_str)
                
                # Validate the structure
                required_keys = [
                    'critical_vulnerabilities', 'medium_risk_findings', 
                    'low_risk_observations', 'attack_vectors', 
                    'recommendations', 'priority_score', 'summary'
                ]
                
                for key in required_keys:
                    if key not in analysis:
                        analysis[key] = [] if key != 'priority_score' else 0
                
                return analysis
            else:
                # Fallback to basic parsing
                return self._fallback_analysis_parsing(ai_response)
                
        except json.JSONDecodeError:
            return self._fallback_analysis_parsing(ai_response)

    def _fallback_analysis_parsing(self, ai_response: str) -> Dict[str, Any]:
        """Fallback parsing when JSON extraction fails"""
        analysis = {
            'critical_vulnerabilities': [],
            'medium_risk_findings': [],
            'low_risk_observations': [],
            'attack_vectors': [],
            'recommendations': [],
            'priority_score': 5,
            'summary': ai_response[:500] + "..." if len(ai_response) > 500 else ai_response
        }
        
        # Try to extract key information using simple text parsing
        lines = ai_response.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip().lower()
            if 'critical' in line or 'high' in line:
                current_section = 'critical_vulnerabilities'
            elif 'medium' in line:
                current_section = 'medium_risk_findings'
            elif 'low' in line:
                current_section = 'low_risk_observations'
            elif 'attack' in line or 'vector' in line:
                current_section = 'attack_vectors'
            elif 'recommend' in line:
                current_section = 'recommendations'
            elif current_section and line and not line.startswith('-'):
                analysis[current_section].append(line)
        
        return analysis

    def _basic_vulnerability_analysis(self, recon_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform basic vulnerability analysis without AI"""
        print_status("Performing basic vulnerability analysis", "info")
        
        vulnerabilities = []
        attack_vectors = []
        recommendations = []
        
        # Analyze DNS information
        dns_info = recon_data.get('dns_info', {})
        if dns_info.get('txt_records'):
            for txt in dns_info['txt_records']:
                if 'google-site-verification' in txt.lower():
                    vulnerabilities.append("Google site verification found in TXT records")
                if 'v=spf1' in txt.lower():
                    vulnerabilities.append("SPF record found - potential email spoofing protection")
        
        # Analyze HTTP information
        http_info = recon_data.get('http_info', {})
        if http_info.get('server'):
            server = http_info['server'].lower()
            if 'apache' in server:
                vulnerabilities.append("Apache server detected - check for common Apache vulnerabilities")
            elif 'nginx' in server:
                vulnerabilities.append("Nginx server detected - check for common Nginx vulnerabilities")
            elif 'iis' in server:
                vulnerabilities.append("IIS server detected - check for common IIS vulnerabilities")
        
        # Check for security headers
        headers = http_info.get('headers', {})
        if not headers.get('X-Frame-Options'):
            vulnerabilities.append("Missing X-Frame-Options header - potential clickjacking vulnerability")
        if not headers.get('X-Content-Type-Options'):
            vulnerabilities.append("Missing X-Content-Type-Options header - potential MIME sniffing vulnerability")
        if not headers.get('Strict-Transport-Security'):
            vulnerabilities.append("Missing HSTS header - potential downgrade attacks")
        
        # Analyze SSL information
        ssl_info = recon_data.get('ssl_info', {})
        if ssl_info:
            if ssl_info.get('not_after'):
                # Check if certificate is expiring soon
                import datetime
                try:
                    expiry = datetime.datetime.strptime(ssl_info['not_after'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry - datetime.datetime.now()).days
                    if days_until_expiry < 30:
                        vulnerabilities.append(f"SSL certificate expires in {days_until_expiry} days")
                except:
                    pass
        
        # Analyze subdomains
        subdomains = recon_data.get('subdomains', [])
        if 'admin' in [s.split('.')[0] for s in subdomains]:
            vulnerabilities.append("Admin subdomain found - potential administrative interface")
        if 'test' in [s.split('.')[0] for s in subdomains]:
            vulnerabilities.append("Test subdomain found - potential testing environment")
        
        # Generate attack vectors
        if vulnerabilities:
            attack_vectors.extend([
                "Information disclosure through DNS records",
                "Server fingerprinting through HTTP headers",
                "Subdomain enumeration and discovery"
            ])
        
        # Generate recommendations
        recommendations.extend([
            "Review and secure DNS records",
            "Implement security headers",
            "Regular SSL certificate monitoring",
            "Subdomain security assessment",
            "Server configuration hardening"
        ])
        
        # Calculate priority score
        priority_score = min(10, len(vulnerabilities) * 2)
        
        return {
            'critical_vulnerabilities': [v for v in vulnerabilities if 'critical' in v.lower() or 'ssl' in v.lower()],
            'medium_risk_findings': [v for v in vulnerabilities if 'ssl' not in v.lower() and 'critical' not in v.lower()],
            'low_risk_observations': [],
            'attack_vectors': attack_vectors,
            'recommendations': recommendations,
            'priority_score': priority_score,
            'summary': f"Basic analysis found {len(vulnerabilities)} potential security issues"
        }

    def generate_report_summary(self, recon_data: Dict[str, Any], ai_analysis: Dict[str, Any]) -> str:
        """Generate a comprehensive report summary"""
        print_status("Generating comprehensive report summary", "info")
        
        summary = f"""
        ╔══════════════════════════════════════════════════════════════╗
        ║                    RECONNAISSANCE REPORT                     ║
        ╚══════════════════════════════════════════════════════════════╝
        
        TARGET: {recon_data.get('target', 'Unknown')}
        PRIORITY SCORE: {ai_analysis.get('priority_score', 0)}/10
        
        ╔══════════════════════════════════════════════════════════════╗
        ║                    EXECUTIVE SUMMARY                         ║
        ╚══════════════════════════════════════════════════════════════╝
        
        {ai_analysis.get('summary', 'No summary available')}
        
        ╔══════════════════════════════════════════════════════════════╗
        ║                  CRITICAL VULNERABILITIES                    ║
        ╚══════════════════════════════════════════════════════════════╝
        """
        
        critical_vulns = ai_analysis.get('critical_vulnerabilities', [])
        if critical_vulns:
            for vuln in critical_vulns:
                summary += f"• {vuln}\n"
        else:
            summary += "No critical vulnerabilities identified.\n"
        
        summary += """
        ╔══════════════════════════════════════════════════════════════╗
        ║                    MEDIUM RISK FINDINGS                      ║
        ╚══════════════════════════════════════════════════════════════╝
        """
        
        medium_risks = ai_analysis.get('medium_risk_findings', [])
        if medium_risks:
            for risk in medium_risks:
                summary += f"• {risk}\n"
        else:
            summary += "No medium risk findings identified.\n"
        
        summary += """
        ╔══════════════════════════════════════════════════════════════╗
        ║                    ATTACK VECTORS                            ║
        ╚══════════════════════════════════════════════════════════════╝
        """
        
        attack_vectors = ai_analysis.get('attack_vectors', [])
        if attack_vectors:
            for vector in attack_vectors:
                summary += f"• {vector}\n"
        else:
            summary += "No specific attack vectors identified.\n"
        
        summary += """
        ╔══════════════════════════════════════════════════════════════╗
        ║                    RECOMMENDATIONS                           ║
        ╚══════════════════════════════════════════════════════════════╝
        """
        
        recommendations = ai_analysis.get('recommendations', [])
        if recommendations:
            for rec in recommendations:
                summary += f"• {rec}\n"
        else:
            summary += "No specific recommendations available.\n"
        
        return summary

    def suggest_next_steps(self, ai_analysis: Dict[str, Any]) -> List[str]:
        """Suggest next steps for bug bounty hunters"""
        priority_score = ai_analysis.get('priority_score', 0)
        next_steps = []
        
        if priority_score >= 8:
            next_steps.extend([
                "Immediate manual verification of critical vulnerabilities",
                "Detailed penetration testing of identified attack vectors",
                "Comprehensive security audit of the target"
            ])
        elif priority_score >= 5:
            next_steps.extend([
                "Manual verification of medium risk findings",
                "Focused testing of specific attack vectors",
                "Targeted security assessment"
            ])
        else:
            next_steps.extend([
                "Basic security testing",
                "Manual verification of findings",
                "Consider expanding scope to related targets"
            ])
        
        return next_steps
