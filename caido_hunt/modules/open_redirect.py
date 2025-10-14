"""
Open Redirect module - detects open redirect vulnerabilities.
This module uses domain validation and business relationship checks to minimize false positives.
"""
from urllib.parse import urlparse, parse_qs, urlencode
import requests, time, re, tldextract
from utils import retry_request

# Known legitimate business relationships and CDN domains
LEGITIMATE_DOMAINS = {
    # AWS/Amazon services
    'wickr.com': ['aws.amazon.com', 'amazon.com', 'amazonaws.com'],
    'amazon.com': ['aws.amazon.com', 'amazonaws.com', 'wickr.com'],
    'www.wickr.com': ['aws.amazon.com', 'amazon.com', 'amazonaws.com'],

    # Microsoft services
    'microsoft.com': ['office.com', 'outlook.com', 'live.com', 'msn.com', 'bing.com'],
    'office.com': ['microsoft.com', 'outlook.com', 'live.com'],

    # Google services
    'google.com': ['youtube.com', 'gmail.com', 'drive.google.com', 'docs.google.com'],
    'youtube.com': ['google.com', 'googlevideo.com'],

    # Common CDNs and services
    'github.com': ['github.io', 'githubusercontent.com'],

    # Social media legitimate redirects
    'facebook.com': ['instagram.com', 'whatsapp.com'],
    'twitter.com': ['t.co'],
}

# Common CDN and service domains that are often legitimate
CDN_DOMAINS = [
    'cloudfront.net', 'cloudflare.com', 'fastly.com', 'jsdelivr.net',
    'cdnjs.cloudflare.com', 'unpkg.com', 'googleapis.com', 'gstatic.com'
]

OPEN_REDIRECT_PAYLOADS = [
    "//evil-domain-test-12345.com",
    "http://evil-domain-test-67890.com",
    "https://malicious-test-abcde.com",
    "/\\evil-redirect-test.com",
    "//attacker-controlled-domain.example",
    "http://redirect-test-hijack.invalid"
]

# Dangerous JavaScript payloads
DANGEROUS_PAYLOADS = [
    "javascript:alert('XSS_TEST')",
    "data:text/html,<script>alert('XSS_TEST')</script>",
    "vbscript:msgbox('XSS_TEST')",
]

def get_domain_info(url):
    """Extract domain information from URL"""
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return None

        extracted = tldextract.extract(url)
        return {
            'domain': extracted.domain + '.' + extracted.suffix,
            'subdomain': extracted.subdomain,
            'full_domain': parsed.netloc.lower(),
            'scheme': parsed.scheme
        }
    except Exception:
        return None

def is_legitimate_redirect(source_domain, target_url):
    """Check if redirect is legitimate based on business relationships"""
    target_info = get_domain_info(target_url)
    if not target_info:
        return False

    target_domain = target_info['domain']

    # Check if it's the same domain or subdomain
    if target_domain == source_domain:
        return True

    # Normalize source domain (remove www prefix for checking)
    normalized_source = source_domain.replace('www.', '') if source_domain.startswith('www.') else source_domain

    # Check legitimate business relationships
    if normalized_source in LEGITIMATE_DOMAINS:
        if target_domain in LEGITIMATE_DOMAINS[normalized_source]:
            return True

    if source_domain in LEGITIMATE_DOMAINS:
        if target_domain in LEGITIMATE_DOMAINS[source_domain]:
            return True

    # Check reverse relationship
    if target_domain in LEGITIMATE_DOMAINS:
        if normalized_source in LEGITIMATE_DOMAINS[target_domain]:
            return True
        if source_domain in LEGITIMATE_DOMAINS[target_domain]:
            return True

    # Check CDN domains
    if any(cdn in target_info['full_domain'] for cdn in CDN_DOMAINS):
        return True

    # Check if it's a subdomain of the same organization
    source_parts = source_domain.split('.')
    target_parts = target_domain.split('.')

    if len(source_parts) >= 2 and len(target_parts) >= 2:
        # Compare the main domain (last two parts)
        if source_parts[-2:] == target_parts[-2:]:
            return True

    return False

def is_dangerous_redirect(target_url):
    """Check if redirect target is dangerous (XSS vectors, etc.)"""
    if not target_url:
        return False

    target_lower = target_url.lower()

    # Check for dangerous schemes
    dangerous_schemes = ['javascript:', 'data:', 'vbscript:', 'file:', 'ftp:']
    for scheme in dangerous_schemes:
        if target_lower.startswith(scheme):
            return True

    # Check for potential XSS patterns
    xss_patterns = [
        'alert(', 'confirm(', 'prompt(', 'document.', 'window.',
        '<script', '</script>', 'eval(', 'settimeout('
    ]

    for pattern in xss_patterns:
        if pattern in target_lower:
            return True

    return False

def test_baseline_redirect(url, param, session, scanner):
    """Test baseline redirect behavior with benign values"""
    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        base = url.split('?', 1)[0]

        # Test with benign internal path
        qs[param] = "/safe-redirect-test"
        query = "&".join(f"{k}={requests.utils.quote(str(v))}" for k, v in qs.items())
        test_url = base + "?" + query

        baseline_resp = retry_request(session.get, test_url, timeout=10, allow_redirects=False)
        return baseline_resp
    except Exception:
        return None

def validate_open_redirect(response, target_payload):
    """Validate that the redirect is actually malicious"""
    if not response or response.status_code not in [301, 302, 303, 307, 308]:
        return False

    location = response.headers.get('Location', '').strip()
    if not location:
        return False

    # Check if it's a dangerous redirect
    if is_dangerous_redirect(location):
        return True

    # Check if payload influenced the redirect location
    if target_payload.lower() in location.lower():
        # Verify it's not a legitimate redirect
        parsed_original = urlparse(response.request.url if hasattr(response, 'request') else response.url)
        source_domain_info = get_domain_info(response.request.url if hasattr(response, 'request') else response.url)

        if source_domain_info:
            source_domain = source_domain_info['domain']
            if not is_legitimate_redirect(source_domain, location):
                return True

    return False

def param_test(url, param, session, scanner):
    """Test parameter for Open Redirect vulnerability with domain validation"""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    base = url.split('?', 1)[0]

    source_domain_info = get_domain_info(url)
    if not source_domain_info:
        return None

    source_domain = source_domain_info['domain']

    # Get baseline behavior
    baseline = test_baseline_redirect(url, param, session, scanner)

    # Test dangerous payloads first (highest priority)
    for payload in DANGEROUS_PAYLOADS:
        qs[param] = payload
        query = "&".join(f"{k}={requests.utils.quote(str(v))}" for k, v in qs.items())
        test_url = base + "?" + query

        if scanner._is_denied(test_url):
            continue

        try:
            resp = retry_request(session.get, test_url, timeout=15, allow_redirects=False)
            if not resp:
                continue

            if validate_open_redirect(resp, payload):
                location = resp.headers.get('Location', '')
                return {
                    "host": scanner.root,
                    "endpoint": test_url,
                    "vul_type": "Open Redirect (High Risk)",
                    "param": param,
                    "payload": payload,
                    "details": f"Dangerous redirect to: {location}",
                    "request_raw": f"GET {test_url} HTTP/1.1\n",
                    "response_raw": f"HTTP/1.1 {resp.status_code}\nLocation: {location}\n",
                    "short_desc": "High-risk open redirect vulnerability",
                    "mitigation": "Validate and whitelist redirect URLs",
                    "confidence": "High"
                }

        except Exception:
            pass

        time.sleep(scanner.sleep)

    # Test external domain redirects
    for payload in OPEN_REDIRECT_PAYLOADS:
        qs[param] = payload
        query = "&".join(f"{k}={requests.utils.quote(str(v))}" for k, v in qs.items())
        test_url = base + "?" + query

        if scanner._is_denied(test_url):
            continue

        try:
            resp = retry_request(session.get, test_url, timeout=15, allow_redirects=False)
            if not resp:
                continue

            if resp.status_code in [301, 302, 303, 307, 308]:
                location = resp.headers.get('Location', '').strip()
                if location:
                    # Check if it's actually redirecting to our test domain
                    if any(test_domain in location.lower() for test_domain in ['evil-domain-test', 'malicious-test', 'attacker-controlled', 'redirect-test-hijack']):
                        # This is a confirmed open redirect to our test domains
                        return {
                            "host": scanner.root,
                            "endpoint": test_url,
                            "vul_type": "Open Redirect (Confirmed)",
                            "param": param,
                            "payload": payload,
                            "details": f"Confirmed redirect to attacker-controlled domain: {location}",
                            "request_raw": f"GET {test_url} HTTP/1.1\n",
                            "response_raw": f"HTTP/1.1 {resp.status_code}\nLocation: {location}\n",
                            "short_desc": "Confirmed open redirect vulnerability",
                            "mitigation": "Implement strict redirect URL validation",
                            "confidence": "High"
                        }

                    # Check if it's redirecting to external domain but not legitimate
                    elif not is_legitimate_redirect(source_domain, location):
                        target_info = get_domain_info(location)
                        if target_info and target_info['domain'] != source_domain:
                            # Double-check if this is a business relationship we missed
                            if not (source_domain == 'wickr.com' and 'aws.amazon.com' in location):
                                return {
                                    "host": scanner.root,
                                    "endpoint": test_url,
                                    "vul_type": "Open Redirect",
                                    "param": param,
                                    "payload": payload,
                                    "details": f"Redirects to external domain: {location}",
                                    "request_raw": f"GET {test_url} HTTP/1.1\n",
                                    "response_raw": f"HTTP/1.1 {resp.status_code}\nLocation: {location}\n",
                                    "short_desc": "Open redirect to external domain",
                                    "mitigation": "Validate and whitelist redirect URLs",
                                    "confidence": "Medium"
                                }

        except Exception:
            pass

        time.sleep(scanner.sleep)

    return None

def form_test(form, session, scanner):
    """Test form fields for Open Redirect with domain validation"""
    for field in list(form.get("inputs", {}).keys())[:3]:
        source_domain_info = get_domain_info(form["action"])
        if not source_domain_info:
            continue

        source_domain = source_domain_info['domain']

        # Test dangerous payloads first
        for payload in DANGEROUS_PAYLOADS[:2]:
            data = {k: (payload if k == field else v) for k, v in form.get("inputs", {}).items()}

            try:
                if form.get("method", "GET").upper() == "POST":
                    resp = retry_request(session.post, form["action"], data=data, timeout=15, allow_redirects=False)
                else:
                    resp = retry_request(session.get, form["action"], params=data, timeout=15, allow_redirects=False)

                if resp and validate_open_redirect(resp, payload):
                    location = resp.headers.get('Location', '')
                    return {
                        "host": scanner.root,
                        "endpoint": form["action"],
                        "vul_type": "Open Redirect (Form)",
                        "param": field,
                        "payload": payload,
                        "details": f"Form redirects to: {location}",
                        "request_raw": f"FORM {form['action']} DATA: {data}",
                        "response_raw": f"HTTP/1.1 {resp.status_code}\nLocation: {location}\n",
                        "short_desc": "Open redirect via form input",
                        "mitigation": "Validate form redirect parameters",
                        "confidence": "High"
                    }

            except Exception:
                pass

            time.sleep(scanner.sleep)

        # Test external domain redirects
        for payload in OPEN_REDIRECT_PAYLOADS[:2]:
            data = {k: (payload if k == field else v) for k, v in form.get("inputs", {}).items()}

            try:
                if form.get("method", "GET").upper() == "POST":
                    resp = retry_request(session.post, form["action"], data=data, timeout=15, allow_redirects=False)
                else:
                    resp = retry_request(session.get, form["action"], params=data, timeout=15, allow_redirects=False)

                if resp and resp.status_code in [301, 302, 303, 307, 308]:
                    location = resp.headers.get('Location', '').strip()
                    if location and not is_legitimate_redirect(source_domain, location):
                        if any(test_domain in location.lower() for test_domain in ['evil-domain-test', 'malicious-test']):
                            return {
                                "host": scanner.root,
                                "endpoint": form["action"],
                                "vul_type": "Open Redirect (Form)",
                                "param": field,
                                "payload": payload,
                                "details": f"Form redirects to test domain: {location}",
                                "request_raw": f"FORM {form['action']} DATA: {data}",
                                "response_raw": f"HTTP/1.1 {resp.status_code}\nLocation: {location}\n",
                                "short_desc": "Confirmed open redirect via form",
                                "mitigation": "Validate form redirect parameters",
                                "confidence": "High"
                            }

            except Exception:
                pass

            time.sleep(scanner.sleep)

    return None

def register():
    return {
        "name": "open_redirect",
        "param_test": param_test,
        "form_test": form_test,
        "description": "Advanced Open Redirect detection with domain validation"
    }
