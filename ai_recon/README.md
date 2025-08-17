# AI Recon - Bug Bounty Reconnaissance CLI Tool

A powerful Python CLI tool for automated bug bounty reconnaissance that performs subdomain enumeration, port scanning, vulnerability lookup, and AI-powered analysis.

## 🚀 Features

- **Subdomain Enumeration**: Uses subfinder (if installed) or falls back to crt.sh API and brute force
- **Port Scanning**: Scans top 100 common ports using nmap or socket-based fallback
- **Vulnerability Lookup**: Queries CVE databases for service-specific vulnerabilities
- **AI Summary**: OpenAI GPT integration for intelligent analysis (with fallback)
- **JSON Output**: Structured reports compatible with Streamlit dashboards
- **Batch Processing**: Scan multiple domains from a text file
- **Rich CLI**: Beautiful terminal output with progress indicators

## 📋 Requirements

- Python 3.8+
- Internet connection for API queries
- Optional: OpenAI API key for AI summaries
- Optional: subfinder tool for enhanced subdomain discovery

## 🛠️ Installation

### 1. Clone or Download
```bash
git clone <repository-url>
cd ai_recon
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Set Up OpenAI API (Optional)
Create a `.env` file in the project root:
```bash
OPENAI_API_KEY=your_openai_api_key_here
```

## 🎯 Usage

### Basic Commands

```bash
# Scan a single domain
python main.py -d example.com

# Scan multiple domains from a file
python main.py -l domains.txt

# Specify custom output filename
python main.py -d example.com -o custom_report.json

# Skip specific scan types
python main.py -d example.com --no-subdomains --no-ai
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-d, --domain` | Single domain to scan |
| `-l, --list` | File containing list of domains |
| `-o, --output` | Custom output filename |
| `--no-subdomains` | Skip subdomain enumeration |
| `--no-ports` | Skip port scanning |
| `--no-vulns` | Skip vulnerability lookup |
| `--no-ai` | Skip AI summary generation |

### Input File Format

For batch scanning, create a text file with one domain per line:
```txt
# domains.txt
example.com
test.com
demo.org
# Comments are ignored
```

## 📊 Output Format

The tool generates JSON reports in the `reports/` folder with the following structure:

```json
{
  "target": "example.com",
  "scan_date": "2025-01-15T10:30:00Z",
  "subdomains": ["www.example.com", "mail.example.com"],
  "open_ports": [80, 443, 22, 3306],
  "vulnerabilities": ["CVE-2021-41773", "CVE-2016-6210"],
  "ai_summary": "AI-generated analysis of findings..."
}
```

## 🔧 Configuration

### Environment Variables

- `OPENAI_API_KEY`: Required for AI-powered summaries
- Other settings use sensible defaults

### Tool Dependencies

- **subfinder**: Enhanced subdomain enumeration (optional)
- **nmap**: Faster port scanning (optional, falls back to socket-based)

## 📁 Project Structure

```
ai_recon/
├── main.py              # CLI entry point
├── modules/             # Core functionality modules
│   ├── __init__.py
│   ├── subdomains.py    # Subdomain enumeration
│   ├── ports.py         # Port scanning
│   ├── vulns.py         # Vulnerability lookup
│   └── ai_summary.py    # AI analysis
├── reports/             # JSON output folder
│   └── sample.json      # Sample report
├── requirements.txt     # Python dependencies
└── README.md           # This file
```

## 🔍 Scan Types

### 1. Subdomain Enumeration
- **Primary**: subfinder tool (if installed)
- **Fallback**: crt.sh SSL certificate API
- **Brute Force**: Common subdomain wordlist

### 2. Port Scanning
- **Primary**: nmap (if available)
- **Fallback**: Socket-based TCP connection testing
- **Coverage**: Top 100 most common ports

### 3. Vulnerability Lookup
- **Service Mapping**: Port-to-service identification
- **CVE Database**: Known vulnerabilities for detected services
- **Banner Grabbing**: Version-specific vulnerability matching

### 4. AI Summary
- **Primary**: OpenAI GPT-3.5-turbo
- **Fallback**: Rule-based analysis
- **Output**: Plain language security insights

## 🚨 Security Considerations

- **Authorized Use Only**: Only scan domains you have permission to test
- **Rate Limiting**: Built-in delays to respect target systems
- **API Limits**: Respect external API rate limits
- **Legal Compliance**: Ensure compliance with local laws and regulations

## 🆘 Troubleshooting

### Common Issues

**Import Errors**: Ensure all dependencies are installed
```bash
pip install -r requirements.txt
```

**Permission Errors**: Check if you have permission to scan the target

**API Key Issues**: Verify your OpenAI API key in the `.env` file

**Port Scanning Fails**: Install nmap for better performance

### Getting Help

1. Check the error messages for specific issues
2. Verify your internet connection
3. Ensure the target domain is accessible
4. Check API key configuration

## 🔮 Future Enhancements

- **Additional APIs**: Integration with more CVE databases
- **Custom Wordlists**: User-defined subdomain lists
- **Report Templates**: Multiple output formats
- **Web Interface**: Streamlit dashboard integration
- **Database Storage**: Persistent scan history

## 📝 Examples

### Single Domain Scan
```bash
python main.py -d example.com
```

### Batch Scan with Custom Output
```bash
python main.py -l targets.txt -o batch_results.json
```

### Quick Port Scan Only
```bash
python main.py -d example.com --no-subdomains --no-vulns --no-ai
```

### Full Reconnaissance
```bash
python main.py -d example.com --output full_scan.json
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- OpenAI for AI analysis capabilities
- crt.sh for SSL certificate data
- The bug bounty community for inspiration

---

**Happy Reconnaissance! 🐛🔍**
