#!/usr/bin/env python3
"""
RedSentinel AI - Setup and Installation Script
Helps users set up the RedSentinel AI environment and dependencies.
"""

import os
import sys
import subprocess
import platform
import shutil
from pathlib import Path

def print_banner():
    """Display setup banner"""
    banner = """
╦═╗┌─┐┌┬┐╔═╗┌─┐┌┐┌┌┬┐┬┌┐┌┌─┐┬    ╔═╗╦
╠╦╝├┤  ││╚═╗├┤ │││ │ ││││├┤ │    ╠═╣║
╩╚═└─┘─┴┘╚═╝└─┘┘└┘ ┴ ┴┘└┘└─┘┴─┘  ╩ ╩╩
    AI-Powered Ethical Hacking Agent
         Setup & Installation
    """
    print(banner)
    print("Version 1.0.0 | For Authorized Testing Only")
    print("-" * 50)

def check_python_version():
    """Check if Python version is compatible"""
    print("🐍 Checking Python version...")
    
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        print(f"   Current version: {sys.version}")
        return False
    else:
        print(f"✅ Python {sys.version.split()[0]} detected")
        return True

def install_python_requirements():
    """Install Python requirements"""
    print("\\n📦 Installing Python dependencies...")
    
    try:
        # Check if pip is available
        subprocess.run([sys.executable, "-m", "pip", "--version"], 
                      check=True, capture_output=True)
        
        # Install requirements
        result = subprocess.run([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Python dependencies installed successfully")
            return True
        else:
            print("❌ Failed to install Python dependencies")
            print(result.stderr)
            return False
            
    except subprocess.CalledProcessError:
        print("❌ pip not found. Please install pip first.")
        return False

def check_security_tools():
    """Check which security tools are available"""
    print("\\n🔧 Checking security tools...")
    
    tools = {
        'nmap': 'Network port scanner',
        'sqlmap': 'SQL injection testing tool',
        'nikto': 'Web vulnerability scanner',
        'wpscan': 'WordPress security scanner',
        'gobuster': 'Directory/file brute forcer'
    }
    
    available_tools = []
    missing_tools = []
    
    for tool, description in tools.items():
        if shutil.which(tool):
            print(f"✅ {tool} - {description}")
            available_tools.append(tool)
        else:
            print(f"❌ {tool} - {description} (not found)")
            missing_tools.append(tool)
    
    return available_tools, missing_tools

def suggest_tool_installation(missing_tools):
    """Suggest how to install missing tools"""
    if not missing_tools:
        return
    
    print("\\n💡 Installation suggestions for missing tools:")
    print("-" * 40)
    
    system = platform.system().lower()
    
    if system == "linux":
        print("For Debian/Ubuntu:")
        if 'nmap' in missing_tools:
            print("  sudo apt install nmap")
        if 'nikto' in missing_tools:
            print("  sudo apt install nikto")
        if 'sqlmap' in missing_tools:
            print("  sudo apt install sqlmap")
        if 'wpscan' in missing_tools:
            print("  gem install wpscan")
        if 'gobuster' in missing_tools:
            print("  sudo apt install gobuster")
    
    elif system == "darwin":  # macOS
        print("For macOS (with Homebrew):")
        if 'nmap' in missing_tools:
            print("  brew install nmap")
        if 'sqlmap' in missing_tools:
            print("  brew install sqlmap")
        if 'wpscan' in missing_tools:
            print("  gem install wpscan")
        if 'gobuster' in missing_tools:
            print("  brew install gobuster")
    
    elif system == "windows":
        print("For Windows:")
        if 'nmap' in missing_tools:
            print("  Download from: https://nmap.org/download.html")
        if 'sqlmap' in missing_tools:
            print("  pip install sqlmap")
        print("  Note: Some tools may require WSL or Docker on Windows")

def setup_playwright():
    """Set up Playwright for browser testing"""
    print("\\n🌐 Setting up Playwright for browser testing...")
    
    try:
        # Check if playwright is installed
        import playwright
        
        # Install browser binaries
        result = subprocess.run([
            sys.executable, "-m", "playwright", "install", "chromium"
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Playwright browser binaries installed")
            return True
        else:
            print("❌ Failed to install Playwright browsers")
            print(result.stderr)
            return False
            
    except ImportError:
        print("⚠️ Playwright not installed (browser testing will be disabled)")
        print("   Install with: pip install playwright")
        return False

def create_directories():
    """Create necessary directories"""
    print("\\n📁 Creating directory structure...")
    
    directories = [
        'config',
        'reports',
        'logs',
        'logs/consent_records'
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"✅ Created: {directory}/")

def setup_config_files():
    """Create initial configuration files"""
    print("\\n⚙️ Setting up configuration files...")
    
    # The main application will create default config files
    # when run for the first time
    print("✅ Configuration files will be created on first run")

def main():
    """Main setup function"""
    print_banner()
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Install Python requirements
    if not install_python_requirements():
        print("⚠️ Some Python dependencies failed to install")
        print("   You may need to install them manually")
    
    # Check security tools
    available_tools, missing_tools = check_security_tools()
    
    if missing_tools:
        suggest_tool_installation(missing_tools)
    
    # Setup Playwright
    setup_playwright()
    
    # Create directories
    create_directories()
    
    # Setup config files
    setup_config_files()
    
    # Final summary
    print("\\n" + "="*50)
    print("🎉 RedSentinel AI Setup Complete!")
    print("="*50)
    
    print("\\n📋 Next Steps:")
    print("1. Configure your Gemini API key (optional):")
    print("   export GEMINI_API_KEY='your-api-key'")
    print("\\n2. Add authorized targets to config/authorized_targets.json")
    print("\\n3. Run your first scan:")
    print("   python redsentinel.py --list-tools")
    print("   python redsentinel.py --url https://example.com --level basic")
    
    if missing_tools:
        print(f"\\n⚠️ Missing tools: {', '.join(missing_tools)}")
        print("   Install them for full functionality")
    
    print(f"\\n✅ Available tools: {', '.join(available_tools) if available_tools else 'None'}")
    print("\\n🛡️ Remember: Only test authorized targets!")

if __name__ == "__main__":
    main()
