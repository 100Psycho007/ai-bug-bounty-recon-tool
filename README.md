# AI Bug Bounty Reconnaissance Tool

A powerful, AI-powered reconnaissance tool designed for bug bounty hunters and security researchers. This tool combines traditional reconnaissance techniques with advanced AI analysis to identify potential vulnerabilities and attack vectors.

## 🚀 Features

### Core Reconnaissance
- **DNS Enumeration**: A, AAAA, MX, NS, TXT, and CNAME record gathering
- **WHOIS Information**: Domain registration details and ownership information
- **SSL Certificate Analysis**: Certificate validation, expiry dates, and SAN information
- **HTTP Header Analysis**: Server fingerprinting and security header assessment
- **Technology Detection**: Automatic detection of web frameworks and technologies
- **Subdomain Discovery**: Common subdomain enumeration and validation

### External Intelligence
- **Shodan Integration**: Internet-wide device and service discovery
- **Censys Integration**: Network infrastructure and service mapping
- **Rate Limiting**: Built-in delays to avoid API rate limits

### AI-Powered Analysis
- **Vulnerability Assessment**: AI-driven identification of security issues
- **Risk Scoring**: Priority-based vulnerability ranking (1-10 scale)
- **Attack Vector Mapping**: Identification of potential exploitation paths
- **Intelligent Recommendations**: AI-generated next steps for bug hunters
- **Fallback Analysis**: Basic analysis when AI is unavailable

### Reporting & Output
- **Multiple Output Levels**: Basic, detailed, and comprehensive reporting
- **JSON Export**: Structured data export for further analysis
- **Rich Terminal Output**: Color-coded, formatted results with tables
- **Report Generation**: Automated report creation and saving

## 📋 Prerequisites

- Python 3.8 or higher
- API keys for enhanced functionality (optional but recommended)

## 🛠️ Installation

### 1. Clone the Repository
```bash
git clone https://github.com/100-Psycho-007/ai-bug-bounty-recon.git
cd ai-bug-bounty-recon
```

### 2. Create Virtual Environment
```bash
python -m venv venv

# On Windows
venv\Scripts\activate

# On macOS/Linux
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Set Up Environment Variables (Optional)
Create a `.env` file in the project root:
```bash
# OpenAI API for AI analysis
OPENAI_API_KEY=your_openai_api_key_here

# Shodan API for external intelligence
SHODAN_API_KEY=your_shodan_api_key_here

# Censys API for network mapping
CENSYS_API_ID=your_censys_api_id_here
CENSYS_API_SECRET=your_censys_api_secret_here
```

## 🚀 Usage

### Basic Usage
```bash
# Analyze a domain
python run.py example.com

# Analyze an IP address
python run.py 192.168.1.1
```

### Advanced Usage
```bash
# Detailed output with AI analysis
python run.py example.com --output detailed

# Full comprehensive report
python run.py example.com --output full

# Disable AI analysis (use basic analysis only)
python run.py example.com --no-ai

# Save detailed reports to files
python run.py example.com --save-report

# Basic output only
python run.py example.com --output basic
```

### Command Line Options
- `--output, -o`: Output detail level (`basic`, `detailed`, `full`)
- `--no-ai`: Disable AI analysis
- `--save-report`: Save detailed reports to files
- `--config`: Path to configuration file

## 📊 Output Examples

### Basic Output
```
=== BASIC RESULTS ===
Target: example.com
Priority Score: 7/10
Critical Vulnerabilities: 2
Medium Risk Findings: 3
```

### Detailed Output
```
=== DETAILED RESULTS ===
Target: example.com
Priority Score: 7/10
Critical Vulnerabilities: 2
Medium Risk Findings: 3

DNS Records
┌──────┬─────────────────┐
│ Type │ Value           │
├──────┼─────────────────┤
│ A    │ 93.184.216.34  │
│ MX   │ mail.example.com│
└──────┴─────────────────┘

Discovered Subdomains
┌──────────────┐
│ Subdomain   │
├──────────────┤
│ www          │
│ mail         │
│ admin        │
└──────────────┘
```

## 🔧 Configuration

### Environment Variables
The tool automatically loads configuration from environment variables:

- `OPENAI_API_KEY`: Required for AI-powered analysis
- `SHODAN_API_KEY`: Required for Shodan intelligence
- `CENSYS_API_ID`: Required for Censys network mapping
- `CENSYS_API_SECRET`: Required for Censys authentication

### API Key Setup

#### OpenAI API
1. Visit [OpenAI Platform](https://platform.openai.com/)
2. Create an account and generate an API key
3. Add to your `.env` file

#### Shodan API
1. Visit [Shodan](https://account.shodan.io/)
2. Create an account and get your API key
3. Add to your `.env` file

#### Censys API
1. Visit [Censys](https://censys.io/)
2. Create an account and generate API credentials
3. Add to your `.env` file

## 📁 Project Structure

```
ai-bug-bounty-recon/
│── src/
│   ├── recon.py         # Core reconnaissance logic
│   ├── ai_analysis.py   # AI analysis logic
│   ├── utils.py         # Helper functions
│── reports/             # Generated reports
│── requirements.txt     # Python dependencies
│── README.md           # This file
│── .gitignore          # Git ignore rules
│── run.py              # Main entry point
```

## 🔒 Security Considerations

- **Legal Compliance**: Only use this tool on targets you have permission to test
- **Rate Limiting**: Built-in delays prevent overwhelming target systems
- **API Security**: Keep your API keys secure and never commit them to version control
- **Responsible Disclosure**: Report vulnerabilities through proper channels

## 🚨 Disclaimer

This tool is designed for legitimate security research and bug bounty hunting. Users are responsible for ensuring they have proper authorization before testing any systems. The authors are not responsible for any misuse of this tool.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- OpenAI for providing the AI analysis capabilities
- Shodan and Censys for external intelligence APIs
- The bug bounty community for inspiration and feedback

## 📞 Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/yourusername/ai-bug-bounty-recon/issues) page
2. Create a new issue with detailed information
3. Include your Python version, OS, and error messages

## 🔄 Updates

Stay updated with the latest features and security improvements by:

1. Following the repository
2. Checking for updates regularly
3. Reading the changelog

---

**Happy Bug Hunting! 🐛🔍**
"# ai-bug-bounty-recon-tool" 
