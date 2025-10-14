#!/usr/bin/env python3
"""
CSRF Detection Module
=====================

Comprehensive Cross-Site Request Forgery (CSRF) detection module.

Features:
- CSRF token presence detection
- State-changing operation identification
- SameSite cookie attribute checking
- Referer header validation testing
- Automated CSRF PoC generation

Author: Llakterian (llakterian@gmail.com)
License: MIT
"""

import re
import logging
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from bs4 import BeautifulSoup
import requests

logger = logging.getLogger(__name__)


@dataclass
class CSRFVulnerability:
    """CSRF vulnerability data structure"""

    url: str
    method: str
    form_action: str
    parameters: Dict[str, str]
    has_token: bool
    token_names: List[str]
    cookie_samesite: Optional[str]
    referer_validated: bool
    severity: str
    cvss_score: float
    evidence: str
    poc_html: str


class CSRFDetector:
    """CSRF vulnerability detection"""

    # Common CSRF token names
    CSRF_TOKEN_PATTERNS = [
        "csrf",
        "csrf_token",
        "csrftoken",
        "_csrf",
        "csrf-token",
        "xsrf",
        "xsrf_token",
        "xsrftoken",
        "_xsrf",
        "token",
        "_token",
        "authenticity_token",
        "auth_token",
        "form_token",
        "security_token",
        "request_token",
        "form_key",
        "__requestverificationtoken",
    ]

    # State-changing keywords
    STATE_CHANGING_KEYWORDS = [
        "delete",
        "remove",
        "update",
        "edit",
        "modify",
        "change",
        "add",
        "create",
        "insert",
        "post",
        "submit",
        "save",
        "transfer",
        "send",
        "payment",
        "purchase",
        "buy",
        "admin",
        "privilege",
        "permission",
        "role",
        "password",
        "email",
        "profile",
        "account",
        "user",
        "settings",
    ]

    def __init__(self, session: requests.Session):
        self.session = session
        self.vulnerabilities: List[CSRFVulnerability] = []

    def analyze_form(
        self, url: str, form_html: str, response: requests.Response
    ) -> Optional[CSRFVulnerability]:
        """Analyze a form for CSRF vulnerabilities"""
        try:
            soup = BeautifulSoup(form_html, "html.parser")
            form = soup.find("form")

            if not form:
                return None

            # Extract form details
            action = form.get("action", "")
            method = form.get("method", "GET").upper()

            # Build absolute action URL
            if action:
                from urllib.parse import urljoin

                action = urljoin(url, action)
            else:
                action = url

            # Extract form inputs
            inputs = form.find_all(["input", "textarea", "select"])
            parameters = {}
            token_names = []
            has_csrf_token = False

            for inp in inputs:
                name = inp.get("name", "")
                value = inp.get("value", "")
                inp_type = inp.get("type", "text").lower()

                if name:
                    parameters[name] = value

                    # Check if this is a CSRF token
                    if self._is_csrf_token(name):
                        has_csrf_token = True
                        token_names.append(name)

            # Check if this is a state-changing form
            is_state_changing = self._is_state_changing(action, method, parameters)

            if not is_state_changing:
                return None  # Not interested in non-state-changing forms

            # Analyze cookies for SameSite attribute
            cookie_samesite = self._check_cookie_samesite(response)

            # Test referer validation
            referer_validated = self._test_referer_validation(
                action, method, parameters
            )

            # Determine vulnerability
            if method == "GET" and is_state_changing:
                # State-changing GET request - always vulnerable
                severity = "Medium"
                cvss_score = 6.5
                evidence = "State-changing operation uses GET method"
                vuln_type = "CSRF (GET)"

            elif method == "POST" and not has_csrf_token:
                # POST without CSRF token
                severity = "High"
                cvss_score = 7.5
                evidence = "State-changing POST request without CSRF token"
                vuln_type = "CSRF (POST)"

            elif cookie_samesite == "None" or cookie_samesite is None:
                # Missing or permissive SameSite attribute
                severity = "Medium"
                cvss_score = 5.5
                evidence = (
                    f"Cookie SameSite attribute is {cookie_samesite or 'not set'}"
                )
                vuln_type = "CSRF (SameSite)"

            else:
                return None  # Likely protected

            # Generate PoC
            poc_html = self._generate_csrf_poc(action, method, parameters, vuln_type)

            csrf_vuln = CSRFVulnerability(
                url=url,
                method=method,
                form_action=action,
                parameters=parameters,
                has_token=has_csrf_token,
                token_names=token_names,
                cookie_samesite=cookie_samesite,
                referer_validated=referer_validated,
                severity=severity,
                cvss_score=cvss_score,
                evidence=evidence,
                poc_html=poc_html,
            )

            self.vulnerabilities.append(csrf_vuln)
            logger.info(f"🔓 CSRF vulnerability found: {action} ({method})")

            return csrf_vuln

        except Exception as e:
            logger.error(f"❌ Error analyzing form: {e}")
            return None

    def _is_csrf_token(self, field_name: str) -> bool:
        """Check if field name matches CSRF token patterns"""
        field_lower = field_name.lower()
        return any(pattern in field_lower for pattern in self.CSRF_TOKEN_PATTERNS)

    def _is_state_changing(
        self, url: str, method: str, parameters: Dict[str, str]
    ) -> bool:
        """Determine if form performs state-changing operation"""
        # POST/PUT/DELETE methods are typically state-changing
        if method in ["POST", "PUT", "DELETE", "PATCH"]:
            return True

        # Check URL and parameters for state-changing keywords
        search_text = (
            f"{url} {' '.join(parameters.keys())} {' '.join(parameters.values())}"
        )
        search_text = search_text.lower()

        return any(keyword in search_text for keyword in self.STATE_CHANGING_KEYWORDS)

    def _check_cookie_samesite(self, response: requests.Response) -> Optional[str]:
        """Check SameSite attribute of session cookies"""
        set_cookie_headers = (
            response.headers.get_list("Set-Cookie")
            if hasattr(response.headers, "get_list")
            else [response.headers.get("Set-Cookie", "")]
        )

        # Also check from raw headers
        if hasattr(response, "raw") and hasattr(response.raw, "headers"):
            for header, value in response.raw.headers.items():
                if header.lower() == "set-cookie":
                    set_cookie_headers.append(value)

        samesite_values = []

        for cookie_str in set_cookie_headers:
            if not cookie_str:
                continue

            # Look for SameSite attribute
            if "samesite=" in cookie_str.lower():
                match = re.search(r"samesite=(\w+)", cookie_str, re.IGNORECASE)
                if match:
                    samesite_values.append(match.group(1))
            else:
                # SameSite not set
                samesite_values.append(None)

        # Return most permissive value
        if None in samesite_values:
            return None
        if "None" in samesite_values:
            return "None"
        if "Lax" in samesite_values:
            return "Lax"
        if "Strict" in samesite_values:
            return "Strict"

        return None

    def _test_referer_validation(
        self, url: str, method: str, parameters: Dict[str, str]
    ) -> bool:
        """Test if endpoint validates Referer header"""
        try:
            # Try without Referer
            response1 = self.session.request(
                method,
                url,
                data=parameters if method == "POST" else None,
                params=parameters if method == "GET" else None,
                timeout=5,
                allow_redirects=False,
            )

            # Try with invalid Referer
            response2 = self.session.request(
                method,
                url,
                data=parameters if method == "POST" else None,
                params=parameters if method == "GET" else None,
                headers={"Referer": "http://evil-attacker.com"},
                timeout=5,
                allow_redirects=False,
            )

            # If both requests succeed with same status, Referer not validated
            if response1.status_code == response2.status_code == 200:
                return False

            return True

        except Exception as e:
            logger.debug(f"Referer validation test failed: {e}")
            return False  # Assume not validated if test fails

    def _generate_csrf_poc(
        self, action: str, method: str, parameters: Dict[str, str], vuln_type: str
    ) -> str:
        """Generate CSRF PoC HTML"""

        # Build form inputs
        inputs_html = []
        for name, value in parameters.items():
            if not self._is_csrf_token(name):  # Don't include CSRF tokens in PoC
                escaped_name = self._html_escape(name)
                escaped_value = self._html_escape(value)
                inputs_html.append(
                    f'    <input type="hidden" name="{escaped_name}" value="{escaped_value}">'
                )

        inputs_str = "\n".join(inputs_html)

        poc = f"""<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC - {vuln_type}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
        }}
        .info {{
            background-color: #f0f0f0;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .warning {{
            background-color: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin-bottom: 20px;
        }}
        button {{
            background-color: #dc3545;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
        }}
        button:hover {{
            background-color: #c82333;
        }}
        pre {{
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 3px;
            overflow-x: auto;
        }}
    </style>
</head>
<body>
    <h1>🔓 CSRF Proof of Concept</h1>

    <div class="warning">
        <strong>⚠️ Warning:</strong> This is a security testing PoC.
        Only use on authorized targets with proper permission.
    </div>

    <div class="info">
        <h3>Vulnerability Details:</h3>
        <ul>
            <li><strong>Type:</strong> {vuln_type}</li>
            <li><strong>Target:</strong> {self._html_escape(action)}</li>
            <li><strong>Method:</strong> {method}</li>
            <li><strong>Impact:</strong> Attacker can perform actions on behalf of authenticated user</li>
        </ul>
    </div>

    <h3>Exploitation Steps:</h3>
    <ol>
        <li>Ensure target user is authenticated to the application</li>
        <li>Click the button below (or page will auto-submit after 3 seconds)</li>
        <li>Observe that the action is performed without user consent</li>
    </ol>

    <h3>Test Form:</h3>
    <form id="csrfForm" action="{self._html_escape(action)}" method="{method}">
{inputs_str}
        <button type="submit">🚀 Trigger CSRF Attack</button>
    </form>

    <h3>Mitigation:</h3>
    <pre>
1. Implement CSRF tokens for all state-changing operations
2. Set SameSite=Strict or SameSite=Lax on session cookies
3. Validate Referer/Origin headers
4. Use custom request headers that cannot be set cross-origin
5. Require re-authentication for sensitive operations
    </pre>

    <script>
        // Auto-submit after 3 seconds
        let countdown = 3;
        const countdownEl = document.createElement('p');
        countdownEl.innerHTML = '<strong>Auto-submitting in: <span id="countdown">3</span> seconds</strong>';
        document.getElementById('csrfForm').insertAdjacentElement('afterend', countdownEl);

        const timer = setInterval(() => {{
            countdown--;
            document.getElementById('countdown').textContent = countdown;
            if (countdown === 0) {{
                clearInterval(timer);
                // Uncomment the next line to enable auto-submit
                // document.getElementById('csrfForm').submit();
                countdownEl.innerHTML = '<strong style="color: #28a745;">✓ Ready to submit (auto-submit disabled for safety)</strong>';
            }}
        }}, 1000);

        // Log submission
        document.getElementById('csrfForm').addEventListener('submit', (e) => {{
            console.log('CSRF PoC submitted to:', '{self._html_escape(action)}');
        }});
    </script>
</body>
</html>"""

        return poc

    def _html_escape(self, text: str) -> str:
        """Escape HTML special characters"""
        import html

        return html.escape(str(text))

    def test_endpoint(self, url: str, method: str = "POST") -> List[CSRFVulnerability]:
        """Test an endpoint for CSRF vulnerabilities"""
        try:
            # First, get the page to analyze forms
            response = self.session.get(url, timeout=10)

            if response.status_code != 200:
                return []

            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")

            vulnerabilities = []

            for form in forms:
                vuln = self.analyze_form(url, str(form), response)
                if vuln:
                    vulnerabilities.append(vuln)

            return vulnerabilities

        except Exception as e:
            logger.error(f"❌ Error testing endpoint: {url} - {e}")
            return []

    def generate_report(self) -> Dict:
        """Generate CSRF vulnerability report"""
        return {
            "total_vulnerabilities": len(self.vulnerabilities),
            "vulnerabilities": [
                {
                    "url": v.url,
                    "method": v.method,
                    "form_action": v.form_action,
                    "severity": v.severity,
                    "cvss_score": v.cvss_score,
                    "has_token": v.has_token,
                    "cookie_samesite": v.cookie_samesite,
                    "evidence": v.evidence,
                    "poc_available": True,
                }
                for v in self.vulnerabilities
            ],
        }
