# Caido Hunt - Ultimate Bug Bounty Scanner

A comprehensive, production-ready vulnerability scanner designed specifically for bug bounty hunters and security researchers.

## 🚀 Features

- **15+ Vulnerability Detection Modules**: XSS, SQLi, RCE, LFI, SSTI, SSRF, Open Redirect, and more
- **Advanced Endpoint Discovery**: Smart crawling and directory enumeration
- **Smart False-Positive Reduction**: Intelligent payload verification and response analysis
- **Multi-threaded Scanning**: Concurrent scanning for improved performance
- **Comprehensive Reporting**: Detailed JSON reports with severity classification
- **Rate Limiting & Stealth**: Configurable delays and stealth options
- **Real-world Payloads**: Production-tested vulnerability detection patterns
- **Session Management**: Advanced cookie and authentication handling

## 📦 Installation

### Quick Install
```bash
git clone https://github.com/llakterian/caido-hunt.git
cd caido-hunt
pip install -r requirements.txt
```

### Development Install
```bash
git clone https://github.com/llakterian/caido-hunt.git
cd caido-hunt
pip install -e .
```

## 🏃 Quick Start

### Basic Scan
```bash
python caido_hunt/main_scanner.py https://target.com
```

### Advanced Scan with Options
```bash
python caido_hunt/main_scanner.py https://target.com \
    --threads 20 \
    --delay 1.0 \
    --max-depth 5 \
    --output custom_report.json \
    --verbose
```

### Using the Original Hunt Interface
```bash
python caido_hunt/hunt.py --target https://target.com --scan-type full
```

## 📁 Project Structure

```
caido-hunt/
├── caido_hunt/              # Main package
│   ├── core/                # Core scanning engine
│   │   ├── scanner_core.py  # Main scanning logic
│   │   ├── config.py        # Configuration management
│   │   └── reporter.py      # Report generation
│   ├── modules/             # Vulnerability detection modules
│   │   ├── xss.py          # XSS detection
│   │   ├── sqli.py         # SQL injection detection
│   │   └── ...             # Other vulnerability modules
│   ├── utils/               # Utility functions
│   │   ├── utils.py        # Common utilities
│   │   └── health_check.py # System health checks
│   ├── hunt.py             # Original CLI interface
│   ├── main_scanner.py     # New streamlined scanner
│   └── gui.py              # Web GUI interface
├── configs/                 # Configuration files
│   └── config.json         # Main configuration
├── scripts/                # Utility scripts
├── wordlists/              # Discovery wordlists
├── tests/                  # Unit tests
├── docs/                   # Documentation
├── reports/                # Generated reports
└── requirements.txt        # Dependencies
```

## ⚙️ Configuration

The scanner uses a JSON configuration file located at `configs/config.json`:

```json
{
  "scanning": {
    "default_threads": 10,
    "default_timeout": 15,
    "default_delay": 0.5,
    "max_depth": 3,
    "max_pages": 1000
  },
  "integrations": {
    "zap": {"enabled": false},
    "nuclei": {"enabled": false},
    "sqlmap": {"enabled": false}
  }
}
```

## 🔍 Supported Vulnerabilities

- **Cross-Site Scripting (XSS)** - Reflected, Stored, DOM-based
- **SQL Injection** - Error-based, Blind, Time-based
- **Remote Code Execution (RCE)** - Command injection, File upload
- **Local File Inclusion (LFI)** - Path traversal, File disclosure
- **Server-Side Template Injection (SSTI)** - Template engine exploitation
- **Server-Side Request Forgery (SSRF)** - Internal service access
- **Open Redirect** - URL redirection abuse
- **XML External Entity (XXE)** - XML parser exploitation
- **NoSQL Injection** - MongoDB, CouchDB injection
- **Header Injection** - HTTP response splitting
- **LDAP Injection** - Directory service exploitation
- **XPath Injection** - XML query manipulation

## 📊 Reporting

The scanner generates comprehensive reports in JSON format:

```json
{
  "target": "https://example.com",
  "scan_timestamp": "2024-01-01T12:00:00",
  "total_vulnerabilities": 5,
  "vulnerabilities_by_severity": {
    "Critical": 1,
    "High": 2,
    "Medium": 2,
    "Low": 0
  },
  "vulnerabilities": [...]
}
```

## 🛡️ Ethical Usage

This tool is designed for legitimate security testing purposes only:

- ✅ **Authorized testing** on systems you own or have explicit permission to test
- ✅ **Bug bounty programs** with proper scope and authorization
- ✅ **Penetration testing** engagements with signed agreements
- ❌ **Unauthorized scanning** of systems you don't own
- ❌ **Malicious activities** or illegal hacking attempts

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Security research community
- Bug bounty platforms
- Open source security tools
- Vulnerability researchers worldwide

## 📞 Support

For questions, issues, or contributions:
- Create an issue on GitHub
- Join our security research community
- Follow responsible disclosure practices

---

**⚠️ Disclaimer**: This tool is for educational and authorized security testing purposes only. Users are responsible for complying with applicable laws and regulations.
