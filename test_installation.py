#!/usr/bin/env python3
"""
Test script to verify AI Bug Bounty Reconnaissance Tool installation
"""

import sys
import importlib

def test_imports():
    """Test if all required modules can be imported"""
    required_modules = [
        'requests',
        'beautifulsoup4',
        'dns',
        'whois',
        'shodan',
        'censys.search',
        'openai',
        'dotenv',
        'colorama',
        'rich',
        'click'
    ]
    
    print("Testing module imports...")
    failed_imports = []
    
    for module in required_modules:
        try:
            if module == 'beautifulsoup4':
                importlib.import_module('bs4')
            elif module == 'dns':
                importlib.import_module('dns.resolver')
            elif module == 'censys.search':
                importlib.import_module('censys.search')
            else:
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
        sys.path.append('src')
        from utils import display_banner, print_status
        print("✓ utils.py")
    except ImportError as e:
        print(f"✗ utils.py: {e}")
        return False
    
    try:
        from recon import ReconnaissanceEngine
        print("✓ recon.py")
    except ImportError as e:
        print(f"✗ recon.py: {e}")
        return False
    
    try:
        from ai_analysis import AIAnalyzer
        print("✓ ai_analysis.py")
    except ImportError as e:
        print(f"✗ ai_analysis.py: {e}")
        return False
    
    return True

def main():
    """Main test function"""
    print("AI Bug Bounty Reconnaissance Tool - Installation Test")
    print("=" * 60)
    
    # Test external dependencies
    failed_external = test_imports()
    
    # Test local modules
    local_modules_ok = test_local_modules()
    
    print("\n" + "=" * 60)
    print("TEST RESULTS:")
    
    if not failed_external and local_modules_ok:
        print("🎉 All tests passed! Your installation is ready.")
        print("\nTo get started:")
        print("1. Set up your API keys in a .env file (see env.example)")
        print("2. Run: python run.py example.com")
    else:
        print("❌ Some tests failed.")
        
        if failed_external:
            print(f"\nFailed external imports: {', '.join(failed_external)}")
            print("Run: pip install -r requirements.txt")
        
        if not local_modules_ok:
            print("\nLocal modules failed to import.")
            print("Check that all source files are present in the src/ directory.")
    
    print("\n" + "=" * 60)

if __name__ == "__main__":
    main()
