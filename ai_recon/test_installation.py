#!/usr/bin/env python3
"""
Test script to verify AI Recon installation
"""

import sys
import importlib

def test_imports():
    """Test if all required modules can be imported"""
    required_modules = [
        'requests',
        'rich',
        'openai',
        'dotenv',
        'nmap',
        'dns'
    ]
    
    print("Testing module imports...")
    failed_imports = []
    
    for module in required_modules:
        try:
            importlib.import_module(module)
            print(f"✓ {module}")
        except ImportError as e:
            print(f"✗ {module}: {e}")
            failed_imports.append(module)
    
    return failed_imports

def test_local_modules():
    """Test if local modules can be imported"""
    print("\nTesting local module imports...")
    
    try:
        from modules.subdomains import SubdomainEnumerator
        print("✓ subdomains.py")
    except ImportError as e:
        print(f"✗ subdomains.py: {e}")
        return False
    
    try:
        from modules.ports import PortScanner
        print("✓ ports.py")
    except ImportError as e:
        print(f"✗ ports.py: {e}")
        return False
    
    try:
        from modules.vulns import VulnerabilityLookup
        print("✓ vulns.py")
    except ImportError as e:
        print(f"✗ vulns.py: {e}")
        return False
    
    try:
        from modules.ai_summary import AISummarizer
        print("✓ ai_summary.py")
    except ImportError as e:
        print(f"✗ ai_summary.py: {e}")
        return False
    
    return True

def test_cli():
    """Test if the CLI can be imported"""
    print("\nTesting CLI entry point...")
    
    try:
        import main
        print("✓ main.py")
        return True
    except ImportError as e:
        print(f"✗ main.py: {e}")
        return False

def main():
    """Main test function"""
    print("AI Recon - Installation Test")
    print("=" * 50)
    
    # Test external dependencies
    failed_external = test_imports()
    
    # Test local modules
    local_modules_ok = test_local_modules()
    
    # Test CLI
    cli_ok = test_cli()
    
    print("\n" + "=" * 50)
    print("TEST RESULTS:")
    
    if not failed_external and local_modules_ok and cli_ok:
        print("🎉 All tests passed! Your installation is ready.")
        print("\nTo get started:")
        print("1. Set up your OpenAI API key in a .env file (optional)")
        print("2. Run: python main.py -d example.com")
        print("3. Check the reports/ folder for output")
    else:
        print("❌ Some tests failed.")
        
        if failed_external:
            print(f"\nFailed external imports: {', '.join(failed_external)}")
            print("Run: pip install -r requirements.txt")
        
        if not local_modules_ok:
            print("\nLocal modules failed to import.")
            print("Check that all source files are present in the modules/ directory.")
        
        if not cli_ok:
            print("\nCLI entry point failed to import.")
            print("Check that main.py is present and properly formatted.")
    
    print("\n" + "=" * 50)

if __name__ == "__main__":
    main()
