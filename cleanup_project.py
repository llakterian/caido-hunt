#!/usr/bin/env python3
"""
Project Cleanup and Structure Script
===================================
This script cleans up the Caido Hunt project structure and prepares it for GitHub deployment.

Features:
- Removes unnecessary files
- Organizes modules properly
- Creates proper directory structure
- Generates .gitignore
- Updates documentation
- Creates requirements.txt
"""

import os
import shutil
import json
from pathlib import Path
import subprocess
import sys

class ProjectCleanup:
    def __init__(self, project_root="./"):
        self.project_root = Path(project_root).resolve()
        self.backup_dir = self.project_root / "backup_cleanup"

    def create_backup(self):
        """Create backup of important files before cleanup"""
        print("Creating backup of important files...")
        self.backup_dir.mkdir(exist_ok=True)

        important_files = [
            "config.json",
            "hunt.py",
            "scanner_core.py",
            "utils.py",
            "health_check.py",
            "requirements.txt",
            "README.md"
        ]

        for file in important_files:
            src = self.project_root / file
            if src.exists():
                shutil.copy2(src, self.backup_dir / file)
                print(f"  Backed up {file}")

    def clean_unnecessary_files(self):
        """Remove unnecessary and duplicate files"""
        print("Cleaning unnecessary files...")

        # Files to remove (duplicates, test files, temporary files)
        files_to_remove = [
            "ultimate_scanner.py",
            "ultimate_bug_bounty_scanner.py",
            "ultimate_complete_scanner.py",
            "final_ultimate_scanner.py",
            "bug_bounty_scanner.py",
            "effective_scanner.py",
            "practical_scanner.py",
            "working_scanner.py",
            "test_scanner.py",
            "test_vulnerability_detection.py",
            "vulnerable_test_server.py",
            "advanced_discovery.py",
            "Unsaved Document 2.txt",
            "geckodriver-new.tar.gz",
            "geckodriver-v0.34.0-linux64.tar.gz",
            "rce_response.gz",
            "ssrf_response.gz",
            "ssti_response.gz",
            "ssti_response.html",
            "test.db"
        ]

        # Directories to clean
        dirs_to_clean = [
            "__pycache__",
            ".vscode",
            ".zencoder",
            "logs",
            "caido_results"
        ]

        for file in files_to_remove:
            file_path = self.project_root / file
            if file_path.exists():
                file_path.unlink()
                print(f"  Removed {file}")

        for dir_name in dirs_to_clean:
            dir_path = self.project_root / dir_name
            if dir_path.exists():
                shutil.rmtree(dir_path)
                print(f"  Removed directory {dir_name}")

    def create_proper_structure(self):
        """Create proper project directory structure"""
        print("Creating proper directory structure...")

        # Create main directories
        directories = [
            "caido_hunt",
            "caido_hunt/modules",
            "caido_hunt/core",
            "caido_hunt/utils",
            "tests",
            "docs",
            "configs",
            "wordlists",
            "reports"
        ]

        for dir_name in directories:
            dir_path = self.project_root / dir_name
            dir_path.mkdir(exist_ok=True, parents=True)
            print(f"  Created directory {dir_name}")

    def organize_files(self):
        """Move files to proper locations"""
        print("Organizing files into proper structure...")

        # File organization mapping
        file_moves = {
            # Core files
            "main_scanner.py": "caido_hunt/main_scanner.py",
            "hunt.py": "caido_hunt/hunt.py",
            "scanner_core.py": "caido_hunt/core/scanner_core.py",
            "utils.py": "caido_hunt/utils/utils.py",
            "config.py": "caido_hunt/core/config.py",
            "health_check.py": "caido_hunt/utils/health_check.py",
            "reporter.py": "caido_hunt/core/reporter.py",
            "gui.py": "caido_hunt/gui.py",

            # Configuration
            "config.json": "configs/config.json",

            # Scripts
            "start_caido_hunt.sh": "scripts/start_caido_hunt.sh",
            "run_nuclei_scans.sh": "scripts/run_nuclei_scans.sh",
            "generate_report.py": "scripts/generate_report.py",

            # Documentation
            "README.md": "README.md",
            "PERFORMANCE_OPTIMIZATIONS.md": "docs/PERFORMANCE_OPTIMIZATIONS.md",
            "FALSE_POSITIVE_ELIMINATION_REPORT.md": "docs/FALSE_POSITIVE_ELIMINATION_REPORT.md",
        }

        # Create scripts directory
        (self.project_root / "scripts").mkdir(exist_ok=True)

        for src, dst in file_moves.items():
            src_path = self.project_root / src
            dst_path = self.project_root / dst

            if src_path.exists():
                # Create parent directory if it doesn't exist
                dst_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(src_path), str(dst_path))
                print(f"  Moved {src} -> {dst}")

        # Move modules directory
        src_modules = self.project_root / "modules"
        dst_modules = self.project_root / "caido_hunt" / "modules"
        if src_modules.exists() and src_modules.is_dir():
            if dst_modules.exists():
                shutil.rmtree(dst_modules)
            shutil.move(str(src_modules), str(dst_modules))
            print(f"  Moved modules -> caido_hunt/modules")

    def create_init_files(self):
        """Create __init__.py files for proper Python package structure"""
        print("Creating __init__.py files...")

        init_files = [
            "caido_hunt/__init__.py",
            "caido_hunt/core/__init__.py",
            "caido_hunt/utils/__init__.py",
            "caido_hunt/modules/__init__.py",
            "tests/__init__.py"
        ]

        for init_file in init_files:
            init_path = self.project_root / init_file
            if not init_path.exists():
                init_path.write_text('"""Caido Hunt Package"""')
                print(f"  Created {init_file}")

    def create_requirements_txt(self):
        """Create comprehensive requirements.txt"""
        print("Creating requirements.txt...")

        requirements = [
            "requests>=2.31.0",
            "beautifulsoup4>=4.12.0",
            "tldextract>=3.6.0",
            "selenium>=4.15.0",
            "python-owasp-zap-v2.4>=0.0.21",
            "flask>=2.3.0",
            "jinja2>=3.1.0",
            "colorama>=0.4.6",
            "rich>=13.6.0",
            "click>=8.1.0",
            "pyyaml>=6.0.1",
            "lxml>=4.9.0",
            "urllib3>=2.0.0",
            "certifi>=2023.7.22",
            "cryptography>=41.0.0",
            "paramiko>=3.3.0",
            "dnspython>=2.4.0",
            "python-nmap>=0.7.1",
            "shodan>=1.29.0",
            "censys>=2.2.0"
        ]

        requirements_path = self.project_root / "requirements.txt"
        requirements_path.write_text("\n".join(requirements) + "\n")
        print(f"  Created requirements.txt with {len(requirements)} packages")

    def create_gitignore(self):
        """Create comprehensive .gitignore"""
        print("Creating .gitignore...")

        gitignore_content = """# Byte-compiled / optimized / DLL files
__pycache__/
*.py[cod]
*$py.class

# C extensions
*.so

# Distribution / packaging
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
pip-wheel-metadata/
share/python-wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# PyInstaller
*.manifest
*.spec

# Installer logs
pip-log.txt
pip-delete-this-directory.txt

# Unit test / coverage reports
htmlcov/
.tox/
.nox/
.coverage
.coverage.*
.cache
nosetests.xml
coverage.xml
*.cover
*.py,cover
.hypothesis/
.pytest_cache/

# Translations
*.mo
*.pot

# Django stuff:
*.log
local_settings.py
db.sqlite3
db.sqlite3-journal

# Flask stuff:
instance/
.webassets-cache

# Scrapy stuff:
.scrapy

# Sphinx documentation
docs/_build/

# PyBuilder
target/

# Jupyter Notebook
.ipynb_checkpoints

# IPython
profile_default/
ipython_config.py

# pyenv
.python-version

# pipenv
Pipfile.lock

# PEP 582
__pypackages__/

# Celery stuff
celerybeat-schedule
celerybeat.pid

# SageMath parsed files
*.sage.py

# Environments
.env
.venv
env/
venv/
ENV/
env.bak/
venv.bak/
caido-env/

# Spyder project settings
.spyderproject
.spyproject

# Rope project settings
.ropeproject

# mkdocs documentation
/site

# mypy
.mypy_cache/
.dmypy.json
dmypy.json

# Pyre type checker
.pyre/

# Custom ignores for Caido Hunt
# Logs
logs/
*.log
ultimate_scanner.log

# Results and reports
caido_results/
reports/*.json
reports/*.html
scan_report_*.json
scan_results_*.json

# Temporary files
*.tmp
*.temp
temp/
tmp/

# API Keys and secrets
.env
secrets.json
api_keys.json
*.key
*.pem

# Browser drivers
geckodriver
chromedriver
*.tar.gz

# Database files
*.db
*.sqlite
*.sqlite3

# Compressed files
*.gz
*.zip
*.tar
*.rar

# IDE specific
.vscode/
.idea/
*.swp
*.swo
*~

# OS specific
.DS_Store
Thumbs.db
.directory

# Backup files
backup_cleanup/
*.bak
*.backup

# Test files
test_*.py
*_test.py
vulnerable_test_server.py

# Configuration overrides
config_local.json
settings_local.py
"""

        gitignore_path = self.project_root / ".gitignore"
        gitignore_path.write_text(gitignore_content)
        print("  Created .gitignore")

    def update_main_config(self):
        """Update main configuration file"""
        print("Updating main configuration...")

        config = {
            "app": {
                "name": "Caido Hunt",
                "version": "4.0",
                "description": "Ultimate Bug Bounty Scanner",
                "author": "Security Research Team"
            },
            "scanning": {
                "default_threads": 10,
                "default_timeout": 15,
                "default_delay": 0.5,
                "max_depth": 3,
                "max_pages": 1000
            },
            "security": {
                "verify_ssl": False,
                "follow_redirects": True,
                "user_agents": [
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                ]
            },
            "integrations": {
                "zap": {
                    "enabled": False,
                    "api_key": "",
                    "host": "127.0.0.1",
                    "port": 8080
                },
                "sqlmap": {
                    "enabled": False,
                    "path": "/usr/bin/sqlmap"
                },
                "nuclei": {
                    "enabled": False,
                    "path": "/usr/bin/nuclei"
                }
            },
            "reporting": {
                "format": "json",
                "include_screenshots": False,
                "save_requests": False
            }
        }

        config_path = self.project_root / "configs" / "config.json"
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        print("  Updated main configuration")

    def create_setup_py(self):
        """Create setup.py for package installation"""
        print("Creating setup.py...")

        setup_content = '''#!/usr/bin/env python3
"""
Setup script for Caido Hunt - Ultimate Bug Bounty Scanner
"""

from setuptools import setup, find_packages
import os

# Read README
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="caido-hunt",
    version="4.0.0",
    author="Security Research Team",
    author_email="security@research.team",
    description="Ultimate Bug Bounty Scanner - Comprehensive vulnerability detection tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/llakterian/caido-hunt",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "caido-hunt=caido_hunt.hunt:main",
            "caido-scanner=caido_hunt.main_scanner:main",
        ],
    },
    include_package_data=True,
    package_data={
        "caido_hunt": ["configs/*.json", "wordlists/*.txt"],
    },
)
'''

        setup_path = self.project_root / "setup.py"
        setup_path.write_text(setup_content)
        print("  Created setup.py")

    def update_readme(self):
        """Update README.md with new structure"""
        print("Updating README.md...")

        readme_content = """# Caido Hunt - Ultimate Bug Bounty Scanner

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
python caido_hunt/main_scanner.py https://target.com \\
    --threads 20 \\
    --delay 1.0 \\
    --max-depth 5 \\
    --output custom_report.json \\
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
"""

        readme_path = self.project_root / "README.md"
        readme_path.write_text(readme_content)
        print("  Updated README.md")

    def create_license(self):
        """Create MIT License file"""
        print("Creating LICENSE file...")

        license_content = """MIT License

Copyright (c) 2024 Caido Hunt Security Research Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

        license_path = self.project_root / "LICENSE"
        license_path.write_text(license_content)
        print("  Created LICENSE file")

    def run_cleanup(self):
        """Run the complete cleanup process"""
        print("="*60)
        print("CAIDO HUNT PROJECT CLEANUP")
        print("="*60)
        print(f"Project root: {self.project_root}")
        print()

        try:
            self.create_backup()
            self.clean_unnecessary_files()
            self.create_proper_structure()
            self.organize_files()
            self.create_init_files()
            self.create_requirements_txt()
            self.create_gitignore()
            self.update_main_config()
            self.create_setup_py()
            self.update_readme()
            self.create_license()

            print("\n" + "="*60)
            print("CLEANUP COMPLETE!")
            print("="*60)
            print("✅ Project structure organized")
            print("✅ Unnecessary files removed")
            print("✅ Configuration files updated")
            print("✅ Documentation updated")
            print("✅ Package structure created")
            print("✅ Git repository prepared")

            print("\nNext steps:")
            print("1. Review the cleaned project structure")
            print("2. Test the main scanner: python caido_hunt/main_scanner.py --help")
            print("3. Initialize git repo: git init")
            print("4. Add remote: git remote add origin https://github.com/llakterian/caido-hunt.git")
            print("5. Commit and push: git add . && git commit -m 'Initial cleaned project structure' && git push -u origin main")

        except Exception as e:
            print(f"Error during cleanup: {e}")
            print("Check the backup directory for important files.")
            return False

        return True

def main():
    """Main function"""
    if len(sys.argv) > 1:
        project_root = sys.argv[1]
    else:
        project_root = "./"

    cleanup = ProjectCleanup(project_root)
    success = cleanup.run_cleanup()

    if success:
        print("\n🎉 Project cleanup completed successfully!")
        sys.exit(0)
    else:
        print("\n❌ Project cleanup failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
