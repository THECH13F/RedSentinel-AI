# RedSentinel AI

![RedSentinel AI Logo](https://via.placeholder.com/400x150/667eea/ffffff?text=RedSentinel+AI)

## 🛡️ AI-Powered Ethical Hacking Security Agent

RedSentinel AI is an intelligent CLI and browser-based cybersecurity tool designed for ethical hacking and security research. It combines the power of AI (Google Gemini) with traditional security tools to provide automated reconnaissance, vulnerability scanning, and intelligent exploitation guidance.

⚠️ **FOR AUTHORIZED TESTING ONLY** - This tool is designed for ethical use on systems you own or have explicit permission to test.

## 🚀 Features

### Core Modules
- **🤖 AI Planner**: Uses Gemini API for intelligent attack planning, CVE searching, and payload generation
- **🔍 Reconnaissance Engine**: Automated information gathering (DNS, ports, services, subdomains)
- **⚡ Tool Runner**: Integrates with popular security tools (nmap, sqlmap, nikto, wpscan, etc.)
- **🌐 Browser Agent**: Client-side testing using Playwright (XSS, CSRF, JavaScript analysis)
- **📊 Report Generator**: Human-readable reports in HTML, JSON, and PDF formats
- **🛡️ Ethical Safeguards**: Target whitelisting, confirmation prompts, and reporting-only mode

### Key Capabilities
- AI-guided scan planning and tool selection
- Automated vulnerability assessment
- Browser-based security testing
- CVE lookup and exploit research
- Custom payload generation
- Comprehensive reporting
- Rate limiting and respectful scanning

## 📋 Prerequisites

### Required Tools
Install these security tools for full functionality:
- **nmap**: Network port scanner and service detection
- **sqlmap**: SQL injection detection and exploitation
- **nikto**: Web server vulnerability scanner
- **wpscan**: WordPress security scanner
- **gobuster**: Directory/file brute forcer

### Python Dependencies
```bash
pip install -r requirements.txt
```

### Browser Automation (Optional)
```bash
pip install playwright
playwright install
```

## 🔧 Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd "RedSentinel AI"
   ```

2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Install security tools** (examples for different systems):
   
   **Kali Linux / Debian:**
   ```bash
   sudo apt update
   sudo apt install nmap sqlmap nikto
   gem install wpscan
   ```
   
   **macOS (with Homebrew):**
   ```bash
   brew install nmap sqlmap nikto
   gem install wpscan
   ```
   
   **Windows:**
   - Download nmap from https://nmap.org/download.html
   - Install Python packages: `pip install sqlmap`

4. **Configure API key** (optional for AI features):
   ```bash
   export GEMINI_API_KEY="your-gemini-api-key"
   ```
   
   Or edit `config/config.json` after first run.

## 🎯 Usage

### Basic Usage

```bash
# Basic web application scan
python redsentinel.py --url https://example.com --level standard

# Deep network scan with AI assistance
python redsentinel.py --ip 192.168.1.100 --level deep --ai-mode smart

# Report-only mode (no exploitation)
python redsentinel.py --url https://testsite.com --report-only

# Custom tool selection
python redsentinel.py --url https://target.com --tools nmap nikto --ai-mode assist
```

### Advanced Usage

```bash
# Multiple targets from file
python redsentinel.py --target-file targets.txt --level standard

# Custom configuration
python redsentinel.py --url https://example.com --config-file custom_config.json

# Specific modules only
python redsentinel.py --url https://example.com --modules recon web-scan browser

# Custom wordlist for directory brute force
python redsentinel.py --url https://example.com --wordlist custom_wordlist.txt
```

### Command Line Options

```
Target Options:
  --url URL              Target URL to scan (e.g., https://example.com)
  --ip IP                Target IP address to scan
  --target-file FILE     File containing list of targets

Scan Configuration:
  --level LEVEL          Scan intensity: basic, standard, deep, custom
  --ai-mode MODE         AI assistance: off, assist, smart, autonomous
  --modules MODULES      Specific modules: recon, vuln-scan, web-scan, exploit, browser
  --tools TOOLS          Specific tools to use

Output Options:
  --output-dir DIR       Output directory for reports (default: ./reports)
  --report-format FMT    Report format: json, html, pdf, all

Ethical Options:
  --report-only          Only perform reconnaissance and reporting
  --whitelist FILE       File containing whitelisted targets
  --confirm              Require confirmation before dangerous operations

Utility Options:
  --list-tools           List all available tools and exit
  --verbose, -v          Increase verbosity (-v, -vv, -vvv)
  --debug                Enable debug mode
```

## 📁 Project Structure

```
RedSentinel AI/
├── redsentinel.py              # Main CLI application
├── modules/                    # Core modules
│   ├── ai_planner.py          # AI-powered planning and assistance
│   ├── recon_engine.py        # Reconnaissance and information gathering
│   ├── tool_runner.py         # Security tool integration and execution
│   ├── browser_agent.py       # Browser-based security testing
│   ├── report_generator.py    # Report generation in multiple formats
│   └── ethical_safeguards.py  # Ethical constraints and safeguards
├── utils/                      # Utility functions
│   ├── logger.py              # Logging configuration
│   └── config.py              # Configuration management
├── config/                     # Configuration files
│   ├── config.json            # Main configuration
│   └── authorized_targets.json # Whitelisted targets
├── reports/                    # Generated reports
├── logs/                       # Application logs
└── requirements.txt           # Python dependencies
```

## ⚙️ Configuration

### Main Configuration (`config/config.json`)
```json
{
  "api": {
    "gemini_api_key": "your-api-key-here",
    "timeout": 30,
    "max_retries": 3
  },
  "scanning": {
    "default_level": "standard",
    "default_ai_mode": "assist",
    "rate_limit": {
      "requests_per_second": 2,
      "concurrent_requests": 1
    }
  },
  "ethical": {
    "require_confirmation": true,
    "auto_report_mode": false
  }
}
```

### Authorized Targets (`config/authorized_targets.json`)
```json
{
  "domains": [
    "example.com",
    "testphp.vulnweb.com"
  ],
  "ip_ranges": [
    "192.168.0.0/16",
    "10.0.0.0/8"
  ],
  "urls": [
    "http://testphp.vulnweb.com/",
    "http://demo.testfire.net/"
  ]
}
```

## 🤖 AI Features

RedSentinel AI integrates with Google Gemini for intelligent security testing:

- **Smart Scan Planning**: AI analyzes targets and recommends optimal scanning strategies
- **CVE Research**: Automatic lookup of known vulnerabilities for discovered services
- **Payload Generation**: Custom exploit payloads based on discovered vulnerabilities
- **Results Analysis**: AI-powered interpretation of scan results and recommendations

To enable AI features, obtain a Gemini API key from Google AI Studio and configure it in the settings.

## 📊 Report Examples

### HTML Report Features
- Executive summary with vulnerability counts
- Color-coded severity levels
- Detailed findings with recommendations
- Screenshots (when available)
- Exportable and shareable format

### JSON Report Structure
```json
{
  "metadata": {
    "tool": "RedSentinel AI",
    "target": "https://example.com",
    "timestamp": "2024-01-01T12:00:00Z"
  },
  "summary": {
    "total_vulnerabilities": 5,
    "critical_vulnerabilities": 0,
    "high_vulnerabilities": 2
  },
  "detailed_results": {
    "recon": {...},
    "vulnerabilities": [...],
    "browser_testing": {...}
  }
}
```

## 🛡️ Ethical Guidelines

### ✅ Authorized Use
- Your own systems and networks
- Systems with explicit written permission
- CTF (Capture The Flag) competitions
- Bug bounty programs within scope
- Authorized penetration testing engagements

### ❌ Prohibited Use
- Testing systems without permission
- Malicious attacks or unauthorized access
- Any illegal or harmful activities
- Violation of terms of service
- Disrupting services or operations

### 🔒 Built-in Safeguards
- Target whitelist verification
- Confirmation prompts for risky operations
- Rate limiting to prevent service disruption
- Reporting-only mode for reconnaissance
- Comprehensive audit logging

## 🤝 Contributing

We welcome contributions to RedSentinel AI! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure code follows Python best practices
5. Submit a pull request with clear description

### Development Setup
```bash
# Install development dependencies
pip install -r requirements.txt
pip install pytest black mypy

# Run tests
pytest

# Format code
black .

# Type checking
mypy .
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

RedSentinel AI is provided for educational and authorized testing purposes only. Users are responsible for ensuring they have proper authorization before testing any systems. The developers assume no liability for misuse of this tool.

## 🆘 Support

- **Issues**: Report bugs and request features on GitHub Issues
- **Documentation**: See the `docs/` folder for detailed documentation
- **Community**: Join our discussions on GitHub Discussions

## 🙏 Acknowledgments

- Google Gemini AI for intelligent analysis capabilities
- The open-source security community for tool integrations
- Ethical hacking community for best practices and guidelines

---

**Remember: With great power comes great responsibility. Use RedSentinel AI ethically and responsibly.**
