# Caido Hunt - Advanced Bug Bounty Scanner

<div align="center">

![Caido Hunt Logo](https://img.shields.io/badge/Caido-Hunt-blue?style=for-the-badge&logo=security&logoColor=white)

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)](https://github.com/user/caido-hunt)

**A comprehensive, production-ready vulnerability scanner for bug bounty hunters and security professionals**

</div>

## 🎯 Overview

Caido Hunt is a powerful, multi-threaded vulnerability scanner designed for bug bounty hunting and security assessments. It combines automated discovery, comprehensive vulnerability detection, and intelligent reporting in a clean, maintainable codebase.

### ✨ Key Features

- **🔍 Comprehensive Detection**: 20+ vulnerability types including XSS, SQLi, LFI, SSRF, RCE, and more
- **🚀 Multi-threaded Scanning**: Parallel processing for maximum efficiency
- **🎨 Multiple Interfaces**: CLI, Web GUI, and API endpoints
- **📊 Advanced Reporting**: JSON/CSV exports with CVSS scoring
- **🛡️ Production Ready**: Clean code, proper error handling, and comprehensive logging
- **🎮 Interactive GUI**: Real-time scanning progress and results visualization
- **⚡ High Performance**: Optimized for speed and resource efficiency

## 🏗️ Architecture

### Core Components

- **`caido_hunt/`** - Main scanner package
  - `main_scanner_fixed.py` - Production-ready scanner with false-positive reduction
  - `scanner_core.py` - Core scanning engine and discovery
  - `modules/` - Individual vulnerability detection modules
  - `utils.py` - Utility functions and helpers

- **`ultimate_scanner_challenge.py`** - Enhanced comprehensive scanner
- **`simple_gui.py`** - Lightweight web interface
- **`unified_gui.py`** - Advanced GUI with real-time features

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- pip package manager
- Virtual environment (recommended)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/llakterian/caido-hunt.git
cd caido-hunt
```

2. **Create virtual environment**
```bash
python -m venv caido-env
source caido-env/bin/activate  # Linux/macOS
# OR
caido-env\Scripts\activate     # Windows
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

### Basic Usage

#### CLI Scanner
```bash
# Basic scan
python ultimate_scanner_challenge.py https://example.com

# Advanced scan with custom settings
python ultimate_scanner_challenge.py https://target.com \
    --threads 20 \
    --timeout 45 \
    --delay 0.5 \
    --max-pages 200 \
    --verbose

# Use the fixed scanner for production
python caido_hunt/main_scanner_fixed.py https://target.com --verbose
```

#### Web GUI
```bash
# Simple GUI
python simple_gui.py --port 5000

# Advanced GUI with real-time features
python unified_gui.py

# Then open http://127.0.0.1:5000 in your browser
```

## 📖 Detailed Usage

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--threads` | Number of concurrent threads | 10 |
| `--timeout` | Request timeout in seconds | 30 |
| `--delay` | Delay between requests | 0.5 |
| `--max-pages` | Maximum pages to scan | 100 |
| `--output-format` | Output format (json/csv) | json |
| `--verbose` | Enable verbose logging | False |

### Vulnerability Detection

#### Supported Vulnerability Types

- **Cross-Site Scripting (XSS)**
  - Reflected XSS
  - Stored XSS
  - DOM XSS

- **SQL Injection**
  - Union-based
  - Boolean blind
  - Time-based blind
  - Error-based

- **File Inclusion**
  - Local File Inclusion (LFI)
  - Remote File Inclusion (RFI)

- **Server-Side Vulnerabilities**
  - Server-Side Request Forgery (SSRF)
  - Remote Code Execution (RCE)
  - Server-Side Template Injection (SSTI)

- **Other Vulnerabilities**
  - Cross-Site Request Forgery (CSRF)
  - Insecure Direct Object Reference (IDOR)
  - Open Redirect
  - Information Disclosure
  - XML External Entity (XXE)

### Advanced Configuration

#### Custom Configuration File
Create a `config.json` file for persistent settings:

```json
{
    "threads": 15,
    "timeout": 60,
    "delay": 1.0,
    "max_pages": 500,
    "user_agent": "Custom User Agent",
    "enable_deep_scan": true,
    "aggressive_mode": false
}
```

## 📊 Reporting

### Report Formats

#### JSON Report Structure
```json
{
    "scan_info": {
        "scan_id": "SCAN_123456",
        "target": "https://example.com",
        "start_time": "2024-01-01T12:00:00",
        "total_vulnerabilities": 5,
        "duration": "45.30 seconds"
    },
    "severity_summary": {
        "Critical": 1,
        "High": 2,
        "Medium": 2
    },
    "vulnerabilities": [...]
}
```

#### CSV Export
Vulnerability data can be exported to CSV for further analysis in spreadsheet applications.

### CVSS Scoring

All vulnerabilities include CVSS v3.1 scoring for standardized risk assessment:

- **Critical**: 9.0 - 10.0
- **High**: 7.0 - 8.9
- **Medium**: 4.0 - 6.9
- **Low**: 0.1 - 3.9

## 🔧 Development

### Project Structure

```
caido-hunt/
├── caido_hunt/                 # Main scanner package
│   ├── core/                  # Core scanning functionality
│   ├── modules/               # Vulnerability detection modules
│   ├── utils/                 # Utility functions
│   └── gui.py                 # GUI components
├── reports/                   # Scan reports and logs
├── scripts/                   # Utility scripts
├── tests/                     # Unit tests
├── configs/                   # Configuration files
├── requirements.txt           # Python dependencies
├── setup.py                   # Package setup
└── README.md                  # This file
```

### Running Tests

```bash
# Run unit tests
python -m pytest tests/

# Run with coverage
python -m pytest tests/ --cov=caido_hunt
```

### Contributing

1. Fork the repository at https://github.com/llakterian/caido-hunt
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 🛡️ Security & Ethics

### Responsible Usage

⚠️ **IMPORTANT SECURITY NOTICE** ⚠️

- **Only scan targets you own or have explicit written permission to test**
- **Never run scans against production systems without authorization**
- **Follow responsible disclosure practices for any vulnerabilities found**
- **Respect rate limits and avoid overwhelming target systems**

### Legal Compliance

Users are responsible for ensuring their use of this tool complies with:
- Local and international laws
- Terms of service of target applications
- Responsible disclosure policies
- Bug bounty program rules and guidelines

## 📈 Performance Tuning

### Optimization Tips

1. **Thread Management**
   - Start with 10 threads for most targets
   - Increase gradually based on server response
   - Monitor system resources

2. **Request Timing**
   - Use appropriate delays to avoid rate limiting
   - Increase timeout for slow servers
   - Implement exponential backoff for retries

3. **Scope Management**
   - Limit page depth for large sites
   - Focus on high-value endpoints
   - Use targeted parameter lists

## 🚨 Troubleshooting

### Common Issues

#### SSL Certificate Errors
```bash
# Disable SSL verification (use with caution)
export PYTHONHTTPSVERIFY=0
```

#### Memory Issues
- Reduce thread count
- Limit max pages
- Increase system memory
- Use incremental scanning

#### Rate Limiting
- Increase delay between requests
- Implement rotating user agents
- Use proxy rotation

### Debug Mode

Enable verbose logging for detailed troubleshooting:

```bash
python ultimate_scanner_challenge.py https://target.com --verbose
```

## 📚 Documentation

### Additional Resources

- [Wiki](https://github.com/llakterian/caido-hunt/wiki) - Detailed documentation
- [Examples](examples/) - Usage examples and tutorials
- [API Reference](docs/api.md) - API documentation
- [Changelog](CHANGELOG.md) - Version history

## 🤝 Support

### Getting Help

- 📖 [Documentation](https://github.com/llakterian/caido-hunt/wiki)
- 🐛 [Issue Tracker](https://github.com/llakterian/caido-hunt/issues)
- 💬 [Discussions](https://github.com/llakterian/caido-hunt/discussions)

### Bug Reports

When reporting bugs, please include:

1. Python version and OS
2. Full command used
3. Target URL (if safe to share)
4. Complete error output
5. Steps to reproduce

## 📋 Changelog

### v2.0.0 (Latest)
- ✅ Fixed syntax errors in ultimate scanner
- ✅ Improved error handling and stability
- ✅ Enhanced vulnerability detection accuracy
- ✅ Added comprehensive reporting
- ✅ Cleaned up project structure

### v1.0.0
- ✅ Initial release
- ✅ Basic vulnerability scanning
- ✅ GUI interface
- ✅ Multi-threading support

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Security research community
- Bug bounty platforms and programs
- Open source security tools ecosystem
- Contributors and testers
- Built by **Llakterian** (llakterian@gmail.com)

## ⭐ Star History

If you find this project useful, please consider giving it a star! ⭐

---

<div align="center">

**Made with ❤️ by Llakterian for the security community**

[Report Bug](https://github.com/llakterian/caido-hunt/issues) • [Request Feature](https://github.com/llakterian/caido-hunt/issues) • [Contribute](CONTRIBUTING.md)

</div>