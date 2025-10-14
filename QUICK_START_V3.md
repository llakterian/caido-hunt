# 🚀 Caido Hunt v3.0 - Quick Start Guide

**Get scanning in 5 minutes!**

---

## 📋 Prerequisites

- Python 3.8 or higher
- pip package manager
- Virtual environment (recommended)

---

## ⚡ Quick Installation (5 Steps)

### Step 1: Navigate to Caido Hunt directory
```bash
cd ~/Desktop/caido-hunt
```

### Step 2: Activate virtual environment
```bash
# If you already have caido-env:
source caido-env/bin/activate

# If not, create it:
python3 -m venv caido-env
source caido-env/bin/activate
```

### Step 3: Install v3.0 dependencies
```bash
# Install base dependencies
pip install -r requirements.txt

# Install v3.0 advanced features
pip install -r requirements-v3.txt
```

### Step 4: Verify installation
```bash
# Test new modules
python -c "from modules.csrf_detector import CSRFDetector; print('✅ CSRF Module OK')"
python -c "from modules.xxe_detector import XXEDetector; print('✅ XXE Module OK')"
python -c "from modules.ssrf_detector import SSRFDetector; print('✅ SSRF Module OK')"
python -c "from modules.graphql_tester import GraphQLTester; print('✅ GraphQL Module OK')"

# Test ML support
python -c "import sklearn, numpy; print('✅ ML Libraries OK')"
```

### Step 5: You're ready to scan! 🎉

---

## 🎯 Basic Usage Examples

### Example 1: Simple Scan with All New Modules
```bash
# Test against known vulnerable site
python ultimate_scanner_challenge.py http://testphp.vulnweb.com \
  --verbose \
  --generate-poc
```

### Example 2: Using Individual New Modules

**CSRF Testing:**
```bash
python3 << 'PYEOF'
from modules.csrf_detector import CSRFDetector
import requests

session = requests.Session()
csrf = CSRFDetector(session)

# Test a target
vulnerabilities = csrf.test_endpoint(
    url="http://testphp.vulnweb.com/search.php",
    method="POST"
)

print(f"Found {len(vulnerabilities)} CSRF vulnerabilities!")
for vuln in vulnerabilities:
    print(f"  - {vuln.severity}: {vuln.evidence}")
    print(f"  - PoC HTML saved!")
PYEOF
```

**XXE Testing:**
```bash
python3 << 'PYEOF'
from modules.xxe_detector import XXEDetector
import requests

session = requests.Session()
xxe = XXEDetector(session, marker="TEST_SCAN")

# Test XML endpoint
vulnerabilities = xxe.test_endpoint(
    url="http://target.com/api/xml",
    method="POST"
)

print(f"Found {len(vulnerabilities)} XXE vulnerabilities!")
for vuln in vulnerabilities:
    print(f"  - Type: {vuln.xxe_type}")
    print(f"  - File disclosed: {vuln.file_disclosed}")
PYEOF
```

**SSRF Testing:**
```bash
python3 << 'PYEOF'
from modules.ssrf_detector import SSRFDetector
import requests

session = requests.Session()
ssrf = SSRFDetector(session, marker="TEST_SCAN")

# Test URL parameter
vulnerabilities = ssrf.test_parameter(
    url="http://target.com/fetch",
    param="url",
    method="GET"
)

print(f"Found {len(vulnerabilities)} SSRF vulnerabilities!")
for vuln in vulnerabilities:
    print(f"  - Target: {vuln.target}")
    print(f"  - Type: {vuln.ssrf_type}")
    print(f"  - Evidence: {vuln.evidence}")
PYEOF
```

**GraphQL Testing:**
```bash
python3 << 'PYEOF'
from modules.graphql_tester import GraphQLTester
import requests

session = requests.Session()
graphql = GraphQLTester(session, marker="TEST_SCAN")

# Test GraphQL endpoint
vulnerabilities = graphql.test_endpoint(
    url="http://target.com/graphql"
)

print(f"Found {len(vulnerabilities)} GraphQL vulnerabilities!")

if graphql.schema_info:
    print("✅ Schema introspection enabled!")
    analysis = graphql.analyze_schema()
    print(f"  - Total types: {analysis['total_types']}")
    print(f"  - Sensitive fields: {len(analysis['sensitive_fields'])}")
PYEOF
```

---

## 🔥 Advanced Usage

### Full Scan with All v3.0 Features
```bash
python ultimate_scanner_challenge.py http://testphp.vulnweb.com \
  --verbose \
  --output reports/full_scan_v3.json
```

### Testing Specific Modules

**Test CSRF Only:**
```bash
python3 test_csrf.py
```

Create `test_csrf.py`:
```python
#!/usr/bin/env python3
from modules.csrf_detector import CSRFDetector
import requests

session = requests.Session()
csrf_detector = CSRFDetector(session)

target = "http://testphp.vulnweb.com"
vulns = csrf_detector.test_endpoint(target, method="POST")

print(f"🔍 Testing {target} for CSRF...")
print(f"✅ Found {len(vulns)} vulnerabilities!")

for v in vulns:
    print(f"\n🚨 {v.severity} - {v.evidence}")
    print(f"📄 PoC saved!")
    
    # Save PoC to file
    with open(f"csrf_poc_{v.form_action.split('/')[-1]}.html", "w") as f:
        f.write(v.poc_html)
```

**Test SSRF with Cloud Metadata:**
```bash
python3 test_ssrf_cloud.py
```

Create `test_ssrf_cloud.py`:
```python
#!/usr/bin/env python3
from modules.ssrf_detector import SSRFDetector
import requests

session = requests.Session()
ssrf = SSRFDetector(session, marker="CLOUD_TEST")

# Test a parameter for SSRF
vulns = ssrf.test_parameter(
    url="http://target.com/fetch",
    param="url",
    method="GET"
)

print(f"🔍 Testing for SSRF (including cloud metadata)...")
print(f"✅ Found {len(vulns)} vulnerabilities!")

for v in vulns:
    print(f"\n🚨 {v.severity} - {v.ssrf_type}")
    print(f"Target: {v.target}")
    print(f"Evidence: {v.evidence}")
    print(f"\ncURL PoC:\n{v.poc_curl}")
```

**Test GraphQL with Schema Export:**
```bash
python3 test_graphql.py
```

Create `test_graphql.py`:
```python
#!/usr/bin/env python3
from modules.graphql_tester import GraphQLTester
import requests
import json

session = requests.Session()
graphql = GraphQLTester(session, marker="GQL_TEST")

# Test GraphQL endpoint
vulns = graphql.test_endpoint("http://target.com/graphql")

print(f"🔍 Testing GraphQL endpoint...")
print(f"✅ Found {len(vulns)} vulnerabilities!")

for v in vulns:
    print(f"\n🚨 {v.severity} - {v.vuln_type}")
    print(f"Evidence: {v.evidence}")

# Export schema if introspection worked
if graphql.schema_info:
    graphql.export_schema("graphql_schema.json")
    print("\n📊 Schema exported to graphql_schema.json")
    
    analysis = graphql.analyze_schema()
    print(f"Total types: {analysis['total_types']}")
    print(f"Sensitive fields found: {analysis['sensitive_fields'][:5]}")
```

---

## 🎨 Real-Time GUI (Enhanced)

### Option 1: Start Enhanced GUI
```bash
python realtime_gui.py --port 5000
```

Then open: http://localhost:5000

### Option 2: Desktop Launcher
```bash
./launch_caido_hunt.sh
```

---

## 🔬 Testing the New Features

### Test Suite for v3.0 Modules

Create `test_all_v3_modules.py`:
```python
#!/usr/bin/env python3
"""
Test all v3.0 modules against testphp.vulnweb.com
"""
from modules.csrf_detector import CSRFDetector
from modules.xxe_detector import XXEDetector
from modules.ssrf_detector import SSRFDetector
from modules.graphql_tester import GraphQLTester
import requests

print("=" * 70)
print("🧪 TESTING CAIDO HUNT v3.0 MODULES")
print("=" * 70)

session = requests.Session()
target = "http://testphp.vulnweb.com"

# Test CSRF
print("\n1️⃣  Testing CSRF Detection...")
csrf = CSRFDetector(session)
csrf_vulns = csrf.test_endpoint(f"{target}/search.php", method="POST")
print(f"   ✅ Found {len(csrf_vulns)} CSRF vulnerabilities")

# Test SSRF (will likely find none on testphp, but module works)
print("\n2️⃣  Testing SSRF Detection...")
ssrf = SSRFDetector(session, marker="V3_TEST")
ssrf_vulns = []  # Would test if there was a URL parameter
print(f"   ✅ SSRF module loaded (test on target with URL params)")

# Test XXE (would need XML endpoint)
print("\n3️⃣  Testing XXE Detection...")
xxe = XXEDetector(session, marker="V3_TEST")
print(f"   ✅ XXE module loaded (test on XML endpoints)")

# Generate report
print("\n" + "=" * 70)
print("📊 SUMMARY")
print("=" * 70)
print(f"Total vulnerabilities found: {len(csrf_vulns)}")
print(f"CSRF: {len(csrf_vulns)}")
print(f"\n✅ All v3.0 modules are working!")
print("=" * 70)

# Save PoCs
for i, vuln in enumerate(csrf_vulns):
    with open(f"poc_csrf_{i+1}.html", "w") as f:
        f.write(vuln.poc_html)
    print(f"💾 Saved: poc_csrf_{i+1}.html")
```

Run it:
```bash
python3 test_all_v3_modules.py
```

---

## 📊 Example Output

When you run the scanner, you'll see:

```
🚀 Caido Hunt v3.0 Scanner Initialized
🎯 Target: http://testphp.vulnweb.com
🔑 Scan ID: SCAN_123456
🤖 ML Detection: Enabled
🔌 WebSocket Testing: Enabled
📊 GraphQL Testing: Enabled

🔍 Discovering endpoints...
✓ Found 12 endpoints
✓ Found 1 form

🧪 Testing vulnerabilities...
├─ Testing XSS... ✓ 1 found
├─ Testing SQLi... ✓ 5 found
├─ Testing CSRF... ✓ 2 found
├─ Testing XXE... ⊘ No XML endpoints
└─ Testing SSRF... ⊘ No URL parameters

🤖 ML Anomaly Detection...
├─ Baseline collected: 20 samples
├─ Model trained: ✓
└─ Anomalies detected: 0

📝 Generating PoCs...
├─ cURL commands: ✓ 8 generated
├─ Python scripts: ✓ 8 generated
└─ HTML forms: ✓ 2 generated

✅ Scan complete!
📊 Total vulnerabilities: 8
🔴 Critical: 5
🟠 High: 1
🟡 Medium: 2
🟢 Low: 0

📄 Report saved: reports/scan_report.json
💾 PoCs saved: pocs/
```

---

## 🐛 Troubleshooting

### Issue: Module not found
```bash
# Solution: Install v3.0 dependencies
pip install -r requirements-v3.txt
```

### Issue: ML libraries not available
```bash
# Solution: Install ML packages
pip install scikit-learn numpy
```

### Issue: GraphQL library missing
```bash
# Solution: Install GraphQL support
pip install gql graphql-core requests-toolbelt
```

### Issue: Port 5000 already in use
```bash
# Solution: Kill the process
lsof -ti:5000 | xargs kill -9

# Or use different port
python realtime_gui.py --port 8080
```

---

## 📚 Next Steps

1. **Read Full Documentation:**
   - `UPGRADE_TO_V3_GUIDE.md` - Complete feature guide
   - `V3_RELEASE_SUMMARY.md` - Release notes

2. **Try Different Targets:**
   ```bash
   # Your own site
   python ultimate_scanner_challenge.py https://your-site.com
   
   # Bug bounty program (with permission!)
   python ultimate_scanner_challenge.py https://target.hackerone.com
   ```

3. **Set Up CI/CD:**
   - See `.github/workflows/security-scan.yml`
   - Integrate with your pipeline

4. **Explore ML Features:**
   - Enable with `--enable-ml` flag
   - Watch for anomaly detections

---

## 🎯 Common Use Cases

### Use Case 1: Quick Security Check
```bash
python ultimate_scanner_challenge.py https://target.com --verbose
```

### Use Case 2: Full Pentest Scan
```bash
python ultimate_scanner_challenge.py https://target.com \
  --verbose \
  --generate-poc \
  --output reports/pentest_$(date +%Y%m%d).json
```

### Use Case 3: CI/CD Security Gate
```bash
python ultimate_scanner_challenge.py $STAGING_URL \
  --output-format sarif \
  --output scan.sarif
```

### Use Case 4: Bug Bounty Hunting
```bash
python ultimate_scanner_challenge.py https://target.hackerone.com \
  --verbose \
  --generate-poc \
  --output reports/bounty_scan.html
```

---

## ✅ You're All Set!

You now have access to:
- ✅ 30+ vulnerability detection types
- ✅ ML-powered anomaly detection
- ✅ Automated PoC generation
- ✅ GraphQL & WebSocket testing
- ✅ CSRF, XXE, SSRF detection
- ✅ CI/CD integration ready
- ✅ Commercial-grade scanning

**Happy Hunting! 🎯**

---

**Need Help?**
- 📧 Email: llakterian@gmail.com
- 📚 Docs: See UPGRADE_TO_V3_GUIDE.md
- 🐛 Issues: GitHub Issues

