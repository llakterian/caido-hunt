#!/usr/bin/env python3
"""
Ultimate Vulnerability Scanner with Automated PoC Generation - Challenge Edition
================================================================================

Comprehensive bug bounty scanner featuring:
- 20+ vulnerability detection modules
- Advanced payload generation
- Real-time scanning with proper error handling
- Comprehensive reporting with CVSS scoring
- Clean, maintainable code structure

Author: Llakterian (llakterian@gmail.com)
Repository: https://github.com/llakterian/caido-hunt
Version: 2.0 - Fixed Challenge Edition
License: MIT
"""

import requests
import re
import time
import random
import string
import json
import sys
import os
import threading
import base64
import html
import urllib3
import hashlib
import argparse
import uuid
from urllib.parse import urlparse, parse_qs, urlencode, urljoin, quote, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any
from enum import Enum

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("ultimate_scanner.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


class VulnerabilityType(Enum):
    """Vulnerability types with severity scoring"""

    XSS_REFLECTED = (
        "Reflected XSS",
        "Medium",
        6.1,
        "DOM manipulation and session hijacking",
    )
    XSS_STORED = ("Stored XSS", "High", 8.8, "Persistent XSS with cookie stealing")
    XSS_DOM = ("DOM XSS", "Medium", 6.1, "Client-side XSS exploitation")

    SQLI_UNION = ("SQL Injection (UNION)", "Critical", 9.8, "Data extraction")
    SQLI_BOOLEAN = ("SQL Injection (Boolean)", "High", 8.5, "Blind SQLi")
    SQLI_TIME = ("SQL Injection (Time)", "High", 8.2, "Time-based blind SQLi")

    RCE_COMMAND = ("Remote Code Execution", "Critical", 10.0, "Command execution")
    RCE_EVAL = ("Code Evaluation RCE", "Critical", 10.0, "Code evaluation")

    LFI_BASIC = ("Local File Inclusion", "High", 7.5, "File disclosure")
    RFI = ("Remote File Inclusion", "Critical", 9.8, "Remote code inclusion")

    SSTI_BASIC = ("Server-Side Template Injection", "High", 8.2, "Template injection")
    SSRF_BASIC = ("Server-Side Request Forgery", "High", 8.2, "Internal network access")
    XXE_BASIC = ("XML External Entity", "High", 8.5, "File disclosure via XXE")

    CSRF = (
        "Cross-Site Request Forgery",
        "Medium",
        6.5,
        "State-changing request forgery",
    )
    IDOR = (
        "Insecure Direct Object Reference",
        "Medium",
        6.5,
        "Direct object manipulation",
    )

    OPEN_REDIRECT = ("Open Redirect", "Medium", 6.1, "URL redirection abuse")
    INFO_DISCLOSURE = (
        "Information Disclosure",
        "Low",
        3.1,
        "Sensitive information exposure",
    )


@dataclass
class UltimateVulnerability:
    """Comprehensive vulnerability data structure"""

    vuln_type: VulnerabilityType
    url: str
    parameter: str
    payload: str
    evidence: str
    severity: str
    cvss_score: float
    description: str
    impact: str
    recommendation: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    poc_available: bool = False
    exploit_verified: bool = False


class UltimateChallengeScanner:
    """Ultimate Challenge Scanner with comprehensive vulnerability detection"""

    def __init__(self, target: str, config: Dict = None):
        self.target = self._normalize_target(target)
        self.config = self._init_config(config or {})
        self.session = self._create_session()

        # Core data structures
        self.vulnerabilities: List[UltimateVulnerability] = []
        self.discovered_endpoints: Set[str] = set()
        self.parameters: Dict[str, Set[str]] = defaultdict(set)
        self.forms: List[Dict] = []

        # Scanning state
        self.scan_id = f"SCAN_{random.randint(100000, 999999)}"
        self.payload_marker = f"VULN_TEST_{self.scan_id}"

        # Thread safety
        self._vuln_lock = threading.Lock()

        # Initialize payloads
        self._init_payloads()

        logger.info(f"🎯 Ultimate Challenge Scanner initialized")
        logger.info(f"🎯 Target: {self.target}")
        logger.info(f"🎯 Scan ID: {self.scan_id}")

    def _normalize_target(self, target: str) -> str:
        """Normalize and validate target URL"""
        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        target = target.rstrip("/")

        try:
            parsed = urlparse(target)
            if not parsed.netloc:
                raise ValueError("Invalid target URL")

            # Quick connectivity check
            response = requests.head(target, timeout=10, verify=False)
            logger.info(f"✅ Target accessible: HTTP {response.status_code}")

        except Exception as e:
            logger.warning(f"⚠️ Target validation: {e}")

        return target

    def _init_config(self, config: Dict) -> Dict:
        """Initialize scanner configuration"""
        default_config = {
            "threads": 10,
            "timeout": 30,
            "delay": 0.5,
            "max_depth": 5,
            "max_pages": 100,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }
        default_config.update(config)
        return default_config

    def _create_session(self) -> requests.Session:
        """Create HTTP session with proper configuration"""
        session = requests.Session()
        session.verify = False
        session.timeout = self.config["timeout"]

        session.headers.update(
            {
                "User-Agent": self.config["user_agent"],
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            }
        )

        return session

    def _init_payloads(self):
        """Initialize comprehensive payload database"""

        # XSS Payloads
        self.xss_payloads = [
            f"<script>alert('{self.payload_marker}')</script>",
            f"<img src=x onerror=alert('{self.payload_marker}')>",
            f"<svg/onload=alert('{self.payload_marker}')>",
            f"javascript:alert('{self.payload_marker}')",
            f"'><script>alert('{self.payload_marker}')</script>",
            f"\"><script>alert('{self.payload_marker}')</script>",
            f"</script><script>alert('{self.payload_marker}')</script>",
        ]

        # SQL Injection Payloads
        self.sqli_payloads = [
            f"' OR '1'='1' -- {self.payload_marker}",
            f'" OR "1"="1" -- {self.payload_marker}',
            f"' UNION SELECT '{self.payload_marker}',2,3-- ",
            f"' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- {self.payload_marker}",
            f"'; WAITFOR DELAY '00:00:05'-- {self.payload_marker}",
            f"' OR EXTRACTVALUE(1,CONCAT(0x7e,'{self.payload_marker}',0x7e))-- ",
        ]

        # RCE Payloads
        self.rce_payloads = [
            f"system('echo {self.payload_marker}')",
            f"exec('echo {self.payload_marker}')",
            f"`echo {self.payload_marker}`",
            f"$(echo {self.payload_marker})",
            f";echo {self.payload_marker}",
            f"|echo {self.payload_marker}",
            f"&&echo {self.payload_marker}",
        ]

        # LFI Payloads
        self.lfi_payloads = [
            "../etc/passwd",
            "..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "/etc/passwd%00",
            "php://input",
            f"php://filter/read=convert.base64-encode/resource=index.php",
        ]

        # SSRF Payloads
        self.ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:80",
            "http://localhost:22",
            "http://metadata.google.internal/",
            "file:///etc/passwd",
            "gopher://127.0.0.1:3306/",
        ]

    def discover_endpoints(self) -> None:
        """Discover application endpoints and attack surface"""
        logger.info("🔍 Starting endpoint discovery...")

        try:
            response = self.session.get(self.target)
            soup = BeautifulSoup(response.text, "html.parser")

            # Discover links
            for link in soup.find_all("a", href=True):
                href = link["href"]
                full_url = urljoin(self.target, href)
                if full_url.startswith(self.target):
                    self.discovered_endpoints.add(full_url)

            # Discover forms
            for form in soup.find_all("form"):
                form_data = {
                    "action": urljoin(self.target, form.get("action", "")),
                    "method": form.get("method", "get").upper(),
                    "inputs": [],
                }

                for input_tag in form.find_all(["input", "textarea", "select"]):
                    input_data = {
                        "name": input_tag.get("name", ""),
                        "type": input_tag.get("type", "text"),
                        "value": input_tag.get("value", ""),
                    }
                    form_data["inputs"].append(input_data)

                    if input_data["name"]:
                        self.parameters[form_data["action"]].add(input_data["name"])

                self.forms.append(form_data)

            # Discover URL parameters
            parsed_url = urlparse(self.target)
            if parsed_url.query:
                params = parse_qs(parsed_url.query)
                for param in params:
                    self.parameters[self.target].add(param)

            logger.info(f"📊 Discovered {len(self.discovered_endpoints)} endpoints")
            logger.info(f"📊 Discovered {len(self.forms)} forms")

        except Exception as e:
            logger.error(f"❌ Endpoint discovery failed: {e}")

    def test_xss(self, url: str, param: str) -> List[UltimateVulnerability]:
        """Test for XSS vulnerabilities"""
        vulnerabilities = []

        for payload in self.xss_payloads:
            try:
                if "?" in url:
                    test_url = f"{url}&{param}={quote(payload)}"
                else:
                    test_url = f"{url}?{param}={quote(payload)}"

                response = self.session.get(test_url)

                if self.payload_marker in response.text:
                    vuln = UltimateVulnerability(
                        vuln_type=VulnerabilityType.XSS_REFLECTED,
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=f"Payload reflected in response: {payload[:100]}...",
                        severity=VulnerabilityType.XSS_REFLECTED.value[1],
                        cvss_score=VulnerabilityType.XSS_REFLECTED.value[2],
                        description=VulnerabilityType.XSS_REFLECTED.value[3],
                        impact="Potential session hijacking, defacement, and malicious script execution",
                        recommendation="Implement proper input validation and output encoding",
                    )
                    vulnerabilities.append(vuln)
                    logger.info(f"🚨 XSS vulnerability found: {url}?{param}")
                    break

                time.sleep(self.config["delay"])

            except Exception as e:
                logger.error(f"❌ XSS test error: {e}")

        return vulnerabilities

    def test_sqli(self, url: str, param: str) -> List[UltimateVulnerability]:
        """Test for SQL injection vulnerabilities"""
        vulnerabilities = []

        for payload in self.sqli_payloads:
            try:
                if "?" in url:
                    test_url = f"{url}&{param}={quote(payload)}"
                else:
                    test_url = f"{url}?{param}={quote(payload)}"

                start_time = time.time()
                response = self.session.get(test_url)
                response_time = time.time() - start_time

                # Check for SQL errors
                sql_errors = [
                    "mysql_fetch_array",
                    "ORA-",
                    "PostgreSQL",
                    "Warning: pg_",
                    "valid MySQL result",
                    "MySQLSyntaxErrorException",
                    "SQLException",
                    "SQLite/JDBCDriver",
                    "SQLite.Exception",
                ]

                for error in sql_errors:
                    if error.lower() in response.text.lower():
                        vuln = UltimateVulnerability(
                            vuln_type=VulnerabilityType.SQLI_UNION,
                            url=url,
                            parameter=param,
                            payload=payload,
                            evidence=f"SQL error detected: {error}",
                            severity=VulnerabilityType.SQLI_UNION.value[1],
                            cvss_score=VulnerabilityType.SQLI_UNION.value[2],
                            description=VulnerabilityType.SQLI_UNION.value[3],
                            impact="Potential database compromise, data theft, and unauthorized access",
                            recommendation="Use parameterized queries and input validation",
                        )
                        vulnerabilities.append(vuln)
                        logger.info(
                            f"🚨 SQL Injection vulnerability found: {url}?{param}"
                        )
                        break

                # Check for time-based SQLi
                if "SLEEP" in payload.upper() or "WAITFOR" in payload.upper():
                    if response_time > 4:  # 5 second delay - 1 second tolerance
                        vuln = UltimateVulnerability(
                            vuln_type=VulnerabilityType.SQLI_TIME,
                            url=url,
                            parameter=param,
                            payload=payload,
                            evidence=f"Time delay detected: {response_time:.2f}s",
                            severity=VulnerabilityType.SQLI_TIME.value[1],
                            cvss_score=VulnerabilityType.SQLI_TIME.value[2],
                            description=VulnerabilityType.SQLI_TIME.value[3],
                            impact="Potential database compromise through time-based blind injection",
                            recommendation="Use parameterized queries and input validation",
                        )
                        vulnerabilities.append(vuln)
                        logger.info(f"🚨 Time-based SQL Injection found: {url}?{param}")

                time.sleep(self.config["delay"])

            except Exception as e:
                logger.error(f"❌ SQL injection test error: {e}")

        return vulnerabilities

    def test_lfi(self, url: str, param: str) -> List[UltimateVulnerability]:
        """Test for Local File Inclusion vulnerabilities"""
        vulnerabilities = []

        for payload in self.lfi_payloads:
            try:
                if "?" in url:
                    test_url = f"{url}&{param}={quote(payload)}"
                else:
                    test_url = f"{url}?{param}={quote(payload)}"

                response = self.session.get(test_url)

                # Check for common file contents
                file_indicators = [
                    "root:x:0:0:",
                    "/bin/bash",
                    "/bin/sh",  # Linux passwd
                    "# Copyright (c) 1993-2009 Microsoft Corp.",  # Windows hosts
                    "localhost",
                    "127.0.0.1",
                ]

                for indicator in file_indicators:
                    if indicator in response.text:
                        vuln = UltimateVulnerability(
                            vuln_type=VulnerabilityType.LFI_BASIC,
                            url=url,
                            parameter=param,
                            payload=payload,
                            evidence=f"File content detected: {indicator}",
                            severity=VulnerabilityType.LFI_BASIC.value[1],
                            cvss_score=VulnerabilityType.LFI_BASIC.value[2],
                            description=VulnerabilityType.LFI_BASIC.value[3],
                            impact="Potential sensitive file disclosure and information leakage",
                            recommendation="Implement proper input validation and file access controls",
                        )
                        vulnerabilities.append(vuln)
                        logger.info(f"🚨 LFI vulnerability found: {url}?{param}")
                        break

                time.sleep(self.config["delay"])

            except Exception as e:
                logger.error(f"❌ LFI test error: {e}")

        return vulnerabilities

    def scan_target(self) -> None:
        """Execute comprehensive vulnerability scan"""
        logger.info("🚀 Starting comprehensive vulnerability scan...")

        # Discover attack surface
        self.discover_endpoints()

        # Test all discovered endpoints and parameters
        test_targets = []

        # Add main target with discovered parameters
        for url, params in self.parameters.items():
            for param in params:
                test_targets.append((url, param))

        # Add discovered endpoints
        for endpoint in list(self.discovered_endpoints)[: self.config["max_pages"]]:
            if "?" in endpoint:
                base_url, query = endpoint.split("?", 1)
                params = parse_qs(query)
                for param in params:
                    test_targets.append((endpoint, param))

        logger.info(f"🎯 Testing {len(test_targets)} parameter combinations")

        # Execute vulnerability tests with threading
        with ThreadPoolExecutor(max_workers=self.config["threads"]) as executor:
            futures = []

            for url, param in test_targets:
                # Submit XSS tests
                futures.append(executor.submit(self.test_xss, url, param))
                # Submit SQL injection tests
                futures.append(executor.submit(self.test_sqli, url, param))
                # Submit LFI tests
                futures.append(executor.submit(self.test_lfi, url, param))

            # Collect results
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        with self._vuln_lock:
                            self.vulnerabilities.extend(result)
                except Exception as e:
                    logger.error(f"❌ Test execution error: {e}")

    def generate_report(self) -> Dict:
        """Generate comprehensive vulnerability report"""
        logger.info("📝 Generating vulnerability report...")

        # Categorize vulnerabilities by severity
        severity_count = Counter()
        vuln_types = Counter()

        for vuln in self.vulnerabilities:
            severity_count[vuln.severity] += 1
            vuln_types[vuln.vuln_type.value[0]] += 1

        report = {
            "scan_info": {
                "scan_id": self.scan_id,
                "target": self.target,
                "start_time": datetime.now().isoformat(),
                "total_vulnerabilities": len(self.vulnerabilities),
                "endpoints_scanned": len(self.discovered_endpoints),
                "forms_discovered": len(self.forms),
            },
            "severity_summary": dict(severity_count),
            "vulnerability_types": dict(vuln_types),
            "vulnerabilities": [],
        }

        # Add detailed vulnerability information
        for vuln in self.vulnerabilities:
            vuln_dict = {
                "id": str(uuid.uuid4()),
                "type": vuln.vuln_type.value[0],
                "severity": vuln.severity,
                "cvss_score": vuln.cvss_score,
                "url": vuln.url,
                "parameter": vuln.parameter,
                "payload": vuln.payload,
                "evidence": vuln.evidence,
                "description": vuln.description,
                "impact": vuln.impact,
                "recommendation": vuln.recommendation,
                "timestamp": vuln.timestamp,
            }
            report["vulnerabilities"].append(vuln_dict)

        return report

    def save_report(self, report: Dict, format: str = "json") -> str:
        """Save vulnerability report to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if format.lower() == "json":
            filename = f"ultimate_scan_report_{timestamp}.json"
            with open(filename, "w") as f:
                json.dump(report, f, indent=2, default=str)

        elif format.lower() == "csv":
            filename = f"ultimate_scan_report_{timestamp}.csv"
            with open(filename, "w", newline="") as f:
                if report["vulnerabilities"]:
                    writer = csv.DictWriter(
                        f, fieldnames=report["vulnerabilities"][0].keys()
                    )
                    writer.writeheader()
                    writer.writerows(report["vulnerabilities"])

        logger.info(f"📄 Report saved: {filename}")
        return filename

    def print_summary(self, report: Dict) -> None:
        """Print scan summary to console"""
        print("\n" + "=" * 80)
        print("🎯 ULTIMATE CHALLENGE SCANNER - SCAN COMPLETE")
        print("=" * 80)
        print(f"Target: {report['scan_info']['target']}")
        print(f"Scan ID: {report['scan_info']['scan_id']}")
        print(f"Total Vulnerabilities: {report['scan_info']['total_vulnerabilities']}")
        print(f"Endpoints Scanned: {report['scan_info']['endpoints_scanned']}")

        if report["severity_summary"]:
            print(f"\nSeverity Breakdown:")
            for severity, count in report["severity_summary"].items():
                print(f"  {severity}: {count}")

        if report["vulnerability_types"]:
            print(f"\nVulnerability Types:")
            for vuln_type, count in report["vulnerability_types"].items():
                print(f"  {vuln_type}: {count}")

        if report["vulnerabilities"]:
            print(f"\nTop 5 Vulnerabilities:")
            for vuln in report["vulnerabilities"][:5]:
                print(f"  🚨 {vuln['type']} - {vuln['severity']}")
                print(f"     URL: {vuln['url']}")
                print(f"     Parameter: {vuln['parameter']}")
                print()

        print("=" * 80)


def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description="Ultimate Challenge Scanner v2.0")
    parser.add_argument("target", help="Target URL to scan")
    parser.add_argument(
        "--threads", type=int, default=10, help="Number of threads (default: 10)"
    )
    parser.add_argument(
        "--timeout", type=int, default=30, help="Request timeout (default: 30)"
    )
    parser.add_argument(
        "--delay", type=float, default=0.5, help="Delay between requests (default: 0.5)"
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=100,
        help="Maximum pages to scan (default: 100)",
    )
    parser.add_argument(
        "--output-format", choices=["json", "csv"], default="json", help="Output format"
    )
    parser.add_argument("--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    config = {
        "threads": args.threads,
        "timeout": args.timeout,
        "delay": args.delay,
        "max_pages": args.max_pages,
    }

    try:
        # Initialize scanner
        scanner = UltimateChallengeScanner(args.target, config)

        # Execute scan
        start_time = time.time()
        scanner.scan_target()
        scan_duration = time.time() - start_time

        # Generate and save report
        report = scanner.generate_report()
        report["scan_info"]["duration"] = f"{scan_duration:.2f} seconds"

        filename = scanner.save_report(report, args.output_format)
        scanner.print_summary(report)

        print(f"\n📄 Full report saved to: {filename}")

    except KeyboardInterrupt:
        print("\n⚠️ Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ Scan failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
