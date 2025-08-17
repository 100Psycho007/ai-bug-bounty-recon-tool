# 🚀 AI Recon - Quick Start Guide

Get up and running with AI Recon in minutes!

## ⚡ 5-Minute Setup

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Test Installation
```bash
python test_installation.py
```

### 3. Run Your First Scan
```bash
# Basic scan
python main.py -d example.com

# With custom output
python main.py -d example.com -o my_report.json
```

## 🔑 OpenAI API Setup (Optional)

For AI-powered vulnerability summaries:

1. Get your API key from [OpenAI Platform](https://platform.openai.com/)
2. Create a `.env` file in the project root:
```bash
OPENAI_API_KEY=your_actual_api_key_here
```

## 📱 Basic Commands

```bash
# Single domain scan
python main.py -d target.com

# Batch scan from file
python main.py -l domains.txt

# Custom output filename
python main.py -d target.com -o results.json

# Skip specific scan types
python main.py -d target.com --no-subdomains --no-ai
```

## 📊 What You'll Get

- **Subdomains**: Discovered subdomains
- **Open Ports**: Active services and ports
- **Vulnerabilities**: CVE identifiers for detected services
- **AI Summary**: Intelligent analysis of findings
- **JSON Output**: Structured reports in `reports/` folder

## 🎯 Example Usage

### Quick Port Scan Only
```bash
python main.py -d example.com --no-subdomains --no-vulns --no-ai
```

### Full Reconnaissance
```bash
python main.py -d example.com --output full_scan.json
```

### Batch Processing
```bash
# Create domains.txt with one domain per line
echo "example.com" > domains.txt
echo "test.com" >> domains.txt

# Run batch scan
python main.py -l domains.txt
```

## 🆘 Troubleshooting

### Common Issues

**Import Errors**: Run `python test_installation.py` to check dependencies

**Permission Errors**: Ensure you have permission to test the target

**API Key Errors**: Make sure your `.env` file is in the project root

### Getting Help

1. Check the full [README.md](README.md)
2. Run the test script: `python test_installation.py`
3. Verify your internet connection
4. Check API key configuration

## 🚨 Important Notes

- **Authorized Use Only**: Only scan domains you have permission to test
- **Rate Limiting**: Built-in delays to respect target systems
- **Legal Compliance**: Ensure compliance with local laws and regulations

## 🎉 Next Steps

1. **Test the tool**: `python main.py -d example.com`
2. **Set up OpenAI API** for AI summaries
3. **Create your domain list** for batch scanning
4. **Check the reports folder** for JSON output
5. **Integrate with Streamlit** for dashboard visualization

---

**Ready to start reconnaissance? Run `python main.py -d example.com`!** 🐛🔍
