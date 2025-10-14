# 🚀 Caido Hunt - Quick Start Guide

Get up and running with Caido Hunt in 5 minutes!

## ⚡ Super Quick Start

```bash
# 1. Clone and setup
git clone https://github.com/llakterian/caido-hunt.git
cd caido-hunt
python -m venv caido-env
source caido-env/bin/activate  # Linux/macOS
# caido-env\Scripts\activate   # Windows

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run your first scan
python ultimate_scanner_challenge.py https://testphp.vulnweb.com --verbose

# 4. Or launch the GUI
python simple_gui.py
```

That's it! 🎉

---

## 📋 Prerequisites

- **Python 3.8+** installed
- **pip** package manager
- **Internet connection**
- **Target with authorization** to scan

Check your Python version:
```bash
python --version
# Should show 3.8 or higher
```

---

## 🎯 Installation

### Option 1: Standard Installation (Recommended)

```bash
# Clone repository
git clone https://github.com/llakterian/caido-hunt.git
cd caido-hunt

# Create virtual environment
python -m venv caido-env

# Activate virtual environment
source caido-env/bin/activate     # Linux/macOS
caido-env\Scripts\activate        # Windows

# Install dependencies
pip install -r requirements.txt

# Verify installation
python ultimate_scanner_challenge.py --help
```

### Option 2: Quick Install (Development)

```bash
git clone https://github.com/llakterian/caido-hunt.git
cd caido-hunt
pip install -e .
```

---

## 🔥 First Scan - CLI

### Basic Scan

Scan a test target (safe, intentionally vulnerable):

```bash
python ultimate_scanner_challenge.py https://testphp.vulnweb.com
```

### Customized Scan

```bash
python ultimate_scanner_challenge.py https://testphp.vulnweb.com \
    --threads 15 \
    --timeout 45 \
    --delay 0.5 \
    --max-pages 200 \
    --verbose
```

### Using the Fixed Scanner

For production use with reduced false positives:

```bash
python caido_hunt/main_scanner_fixed.py https://target.com --verbose
```

---

## 🎨 First Scan - GUI

### Simple GUI (Recommended for Beginners)

```bash
# Start the server
python simple_gui.py --port 5000

# Browser opens automatically at http://127.0.0.1:5000
# If not, open manually
```

**In the GUI:**
1. Enter target URL (e.g., `https://testphp.vulnweb.com`)
2. Adjust settings (threads, delay, timeout)
3. Click "Start Scan"
4. Watch real-time results
5. Export as JSON or CSV

### Advanced GUI (Real-time Updates)

Requires `flask-socketio`:

```bash
pip install flask-socketio

# Start the advanced GUI
python unified_gui.py --port 5000
```

Features:
- Real-time progress updates
- Live vulnerability feed
- WebSocket-based communication

---

## 📊 Understanding Results

### Severity Levels

- **Critical** (9.0-10.0): Immediate action required
- **High** (7.0-8.9): Fix as soon as possible
- **Medium** (4.0-6.9): Should be addressed
- **Low** (0.1-3.9): Minor issues

### Report Files

Scans generate reports in the `reports/` directory:

```bash
ultimate_scan_report_20240114_120000.json
```

### Viewing Reports

**JSON format:**
```bash
cat ultimate_scan_report_*.json | python -m json.tool
```

**CSV format:**
```bash
# Export from GUI or convert JSON to CSV
```

---

## 🎓 Common Use Cases

### 1. Quick Bug Bounty Scan

```bash
# Fast, aggressive scan
python ultimate_scanner_challenge.py https://target.com \
    --threads 20 \
    --delay 0.3 \
    --max-pages 500 \
    --verbose
```

### 2. Stealth/Careful Scan

```bash
# Slow, careful scan to avoid detection
python ultimate_scanner_challenge.py https://target.com \
    --threads 5 \
    --delay 2.0 \
    --timeout 60 \
    --max-pages 100
```

### 3. Deep Application Scan

```bash
# Comprehensive deep scan
python ultimate_scanner_challenge.py https://target.com \
    --threads 10 \
    --delay 1.0 \
    --max-pages 1000 \
    --verbose
```

### 4. API Endpoint Testing

```bash
# Focused API testing
python ultimate_scanner_challenge.py https://api.target.com/v1 \
    --threads 8 \
    --delay 0.5
```

---

## 🔧 Configuration Tips

### Optimal Settings for Different Targets

| Target Type | Threads | Delay | Timeout | Max Pages |
|-------------|---------|-------|---------|-----------|
| Small site  | 5-10    | 0.5s  | 30s     | 100       |
| Medium site | 10-15   | 1.0s  | 45s     | 500       |
| Large site  | 15-20   | 1.5s  | 60s     | 1000+     |
| API         | 8-12    | 0.5s  | 30s     | 200       |

### Performance Tuning

**Speed up scans:**
- Increase threads (10-20)
- Reduce delay (0.3-0.5s)
- Lower timeout (20-30s)

**Reduce load/be stealthy:**
- Decrease threads (3-5)
- Increase delay (2-5s)
- Increase timeout (60-90s)

---

## 🛡️ Safety First

### Before You Scan

✅ **DO:**
- Get written authorization
- Read the scope carefully
- Start with low impact settings
- Test on staging/test environments
- Follow responsible disclosure

❌ **DON'T:**
- Scan without permission
- Exceed agreed scope
- Test production during business hours (unless approved)
- Share findings publicly without permission
- Use aggressive settings on sensitive targets

### Test Targets (Legal to Scan)

Practice on these intentionally vulnerable sites:

- https://testphp.vulnweb.com
- http://testhtml5.vulnweb.com
- http://testasp.vulnweb.com
- https://www.hackthissite.org
- https://www.root-me.org

---

## 🐛 Troubleshooting

### Common Issues

**1. "No module named 'requests'"**
```bash
pip install -r requirements.txt
```

**2. "Permission denied" or "Port already in use"**
```bash
# Use different port
python simple_gui.py --port 5001
```

**3. "Target not accessible"**
```bash
# Check if target is reachable
curl -I https://target.com
```

**4. SSL Certificate errors**
```bash
# Already handled by scanner (verify=False)
# But ensure you have latest urllib3
pip install --upgrade urllib3 requests
```

**5. Memory issues on large scans**
```bash
# Reduce max pages and threads
python ultimate_scanner_challenge.py https://target.com \
    --threads 5 \
    --max-pages 200
```

---

## 📚 Next Steps

### Learn More

1. **Read the full README**: [README.md](README.md)
2. **Study vulnerability types**: Check OWASP Top 10
3. **Explore modules**: Look in `caido_hunt/modules/`
4. **Customize payloads**: Edit detection modules
5. **Contribute**: See [CONTRIBUTING.md](CONTRIBUTING.md)

### Advanced Features

```bash
# Export specific format
python ultimate_scanner_challenge.py https://target.com \
    --output-format csv

# Verbose logging for debugging
python ultimate_scanner_challenge.py https://target.com \
    --verbose

# View scan logs
tail -f reports/ultimate_scanner.log
```

---

## 💡 Pro Tips

1. **Start Small**: Begin with a small page limit, then scale up
2. **Monitor Resources**: Watch CPU/memory usage during scans
3. **Rate Limiting**: If you get rate limited, increase delays
4. **False Positives**: Verify findings manually before reporting
5. **Save Results**: Always export reports for documentation
6. **Stay Updated**: Pull latest changes regularly
   ```bash
   git pull origin main
   pip install -r requirements.txt --upgrade
   ```

---

## 🆘 Getting Help

### Resources

- **Documentation**: [Full README](README.md)
- **Issues**: [GitHub Issues](https://github.com/llakterian/caido-hunt/issues)
- **Discussions**: [GitHub Discussions](https://github.com/llakterian/caido-hunt/discussions)
- **Email**: llakterian@gmail.com

### Report Problems

Found a bug? [Create an issue](https://github.com/llakterian/caido-hunt/issues/new?template=bug_report.md)

Want a feature? [Request it](https://github.com/llakterian/caido-hunt/issues/new?template=feature_request.md)

---

## 🎯 Quick Reference Card

```bash
# Installation
git clone https://github.com/llakterian/caido-hunt.git && cd caido-hunt
python -m venv caido-env && source caido-env/bin/activate
pip install -r requirements.txt

# Basic scan
python ultimate_scanner_challenge.py https://target.com

# GUI scan
python simple_gui.py

# Custom scan
python ultimate_scanner_challenge.py https://target.com \
    --threads 15 --delay 1.0 --verbose

# View results
cat reports/ultimate_scan_report_*.json | python -m json.tool

# Get help
python ultimate_scanner_challenge.py --help
```

---

## ✅ Checklist for Your First Scan

- [ ] Python 3.8+ installed
- [ ] Repository cloned
- [ ] Virtual environment activated
- [ ] Dependencies installed
- [ ] Authorization obtained for target
- [ ] Target URL prepared
- [ ] Scan settings configured
- [ ] Ready to scan!

---

**🎉 Congratulations!**

You're now ready to use Caido Hunt for your security assessments. Remember to always scan responsibly and ethically.

**Happy hunting! 🎯**

---

Built by [Llakterian](https://github.com/llakterian) | [llakterian@gmail.com](mailto:llakterian@gmail.com)

Repository: [github.com/llakterian/caido-hunt](https://github.com/llakterian/caido-hunt)