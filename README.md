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

# 🕵️‍♂️ AI Bug Bounty Recon Tool

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-Latest-FF4B4B?logo=streamlit&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![GitHub stars](https://img.shields.io/github/stars/100Psycho007/ai-bug-bounty-recon-tool?style=social)
![Status](https://img.shields.io/badge/Status-Active-success)
[![CI Tests](https://github.com/100Psycho007/ai-bug-bounty-recon-tool/actions/workflows/tests.yml/badge.svg)](https://github.com/100Psycho007/ai-bug-bounty-recon-tool/actions)

An **AI-powered reconnaissance assistant** designed for bug bounty hunters, security researchers, and penetration testers.  
It automates **subdomain discovery, port scanning, vulnerability hints, and AI-based summaries** — all in a clean, web-based Streamlit dashboard.

---

## 🚀 Features

- **Subdomain Discovery** — Uses `subfinder` for finding hidden assets.
- **Port Scanning** — Integrates with `nmap` for fast and detailed port mapping.
- **AI Summaries** — Uses GPT to analyze recon results and provide actionable insights.
- **Dashboard UI** — Built with Streamlit for an intuitive, professional interface.
- **Export Reports** — Save recon results in CSV/JSON formats for later use.

---

## 📸 Screenshot
> *(Add a screenshot of the tool’s dashboard here once you run it locally)*

---

## ⚙️ Installation

### 1️⃣ Clone the repository
```bash
git clone https://github.com/100Psycho007/ai-bug-bounty-recon-tool.git
cd ai-bug-bounty-recon-tool
```
### 2️⃣ Create a virtual environment
```bash
python -m venv venv
source venv/bin/activate   # macOS/Linux
venv\Scripts\activate      # Windows
```
### 3️⃣ Install dependencies
```bash
pip install -r requirements.txt
```
### 4️⃣ (Optional) Install external tools
- Subfinder – Installation Guide
- Nmap – Download

### 5️⃣ Set environment variables
Create a .env file:
```env
OPENAI_API_KEY=your_api_key_here
```

## ▶️ Usage
```bash
streamlit run app.py
```
Open your browser and go to:
```
http://localhost:8501
```

## 📂 Project Structure
```bash
ai-bug-bounty-recon-tool/
│── app.py                 # Main Streamlit app
│── recon/
│   ├── subdomain_finder.py
│   ├── port_scanner.py
│   ├── ai_analyzer.py
│── requirements.txt
│── README.md
│── .env.example
│── reports/               # Generated recon reports
│── .github/workflows/tests.yml   # GitHub Actions CI/CD config
```

## 📜 License
This project is licensed under the MIT License.

## 🌟 Contributing
Contributions, issues, and feature requests are welcome!
Feel free to star the repo if you find it useful.

## 🙌 Acknowledgements
- ProjectDiscovery Subfinder
- Nmap
- OpenAI
- Streamlit

💡 This project was built as part of my Cybersecurity & AI Portfolio, showcasing automation, AI integration, and security tooling expertise.

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
