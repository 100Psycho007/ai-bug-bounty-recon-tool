# 🚀 Quick Start Guide

Get up and running with the AI Bug Bounty Reconnaissance Tool in minutes!

## ⚡ 5-Minute Setup

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Test Installation
```bash
python test_installation.py
```

### 3. Run Demo (No API Keys Required)
```bash
python demo.py
```

### 4. Set Up API Keys (Optional but Recommended)
Copy `env.example` to `.env` and add your keys:
```bash
cp env.example .env
# Edit .env with your actual API keys
```

### 5. Run Your First Scan
```bash
python run.py example.com
```

## 🔑 Required vs Optional APIs

| API | Required | Purpose |
|-----|----------|---------|
| **OpenAI** | ✅ **Yes** | AI-powered vulnerability analysis |
| Shodan | ❌ No | External intelligence gathering |
| Censys | ❌ No | Network infrastructure mapping |

## 📱 Basic Commands

```bash
# Basic scan
python run.py target.com

# Detailed output
python run.py target.com --output detailed

# Save reports
python run.py target.com --save-report

# No AI analysis
python run.py target.com --no-ai
```

## 🆘 Troubleshooting

### Common Issues

**Import Errors**: Run `python test_installation.py` to check dependencies

**API Key Errors**: Make sure your `.env` file is in the project root

**Permission Errors**: Ensure you have permission to test the target

### Getting Help

1. Check the full [README.md](README.md)
2. Run the demo: `python demo.py`
3. Test installation: `python test_installation.py`

## 🎯 Next Steps

1. **Learn the tool**: Run `python demo.py`
2. **Set up APIs**: Configure your `.env` file
3. **Start hunting**: `python run.py your-target.com`
4. **Save reports**: Use `--save-report` flag
5. **Customize**: Modify `src/` files for your needs

---

**Ready to start bug hunting? Run `python demo.py` to see the tool in action!** 🐛🔍
