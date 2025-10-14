"""
Server-Side Template Injection (SSTI) module - detects SSTI vulnerabilities.
This module uses advanced detection techniques to minimize false positives.
"""
from urllib.parse import urlparse, parse_qs, urlencode
import requests, time, re, random, string
from utils import retry_request

# Mathematical SSTI payloads with expected results
SSTI_MATH_PAYLOADS = [
    {"template": "{{{}}}", "expr": "31337+1337", "expected": "32674"},
    {"template": "${{{}}}", "expr": "12345*2", "expected": "24690"},
    {"template": "<%= {} %>", "expr": "7919*13", "expected": "102947"},
    {"template": "#{{{}}}", "expr": "9999+1", "expected": "10000"},
    {"template": "{{{}}}", "expr": "8*8*8", "expected": "512"},
]

# Template-specific payloads for different engines
TEMPLATE_PAYLOADS = [
    # Jinja2/Flask
    {"payload": "{{config}}", "indicators": ["SECRET_KEY", "DEBUG", "TESTING"]},
    {"payload": "{{''.__class__.__mro__[1].__subclasses__()}}", "indicators": ["<class", "subprocess", "os"]},

    # Twig
    {"payload": "{{_self}}", "indicators": ["Twig_Template", "twig"]},

    # Smarty
    {"payload": "{$smarty.version}", "indicators": ["smarty", "version"]},

    # Velocity
    {"payload": "#set($x='')${x.class}", "indicators": ["java.lang", "String"]},

    # Freemarker
    {"payload": "${class.forName}", "indicators": ["java.lang.Class", "forName"]},
]

def generate_unique_calculation():
    """Generate a unique mathematical calculation for testing"""
    a = random.randint(1000, 9999)
    b = random.randint(100, 999)
    operation = random.choice(['+', '*'])

    if operation == '+':
        result = str(a + b)
    else:
        result = str(a * b)

    return f"{a}{operation}{b}", result

def test_baseline_response(url, param, session, scanner):
    """Get baseline response with benign payload"""
    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        base = url.split('?', 1)[0]

        # Test with benign payload that looks template-like but harmless
        qs[param] = "benign{{test}}value"
        query = "&".join(f"{k}={requests.utils.quote(str(v))}" for k, v in qs.items())
        test_url = base + "?" + query

        baseline_resp = retry_request(session.get, test_url, timeout=10)
        return baseline_resp
    except Exception:
        return None

def is_mathematical_result(response_text, expression, expected_result):
    """Check if the mathematical expression was actually evaluated"""
    if not response_text or not expected_result:
        return False

    response_lower = response_text.lower()

    # Look for the exact result
    if expected_result in response_text:
        # Verify it's not just parameter reflection
        if expression not in response_text:
            # Check if result appears in contexts suggesting evaluation
            lines = response_text.split('\n')
            for line in lines:
                if expected_result in line:
                    # Not in URL parameters or form values
                    if not any(prefix in line.lower() for prefix in ['value=', 'href=', 'url=', 'action=']):
                        # Check for evaluation context
                        if any(context in line.lower() for context in ['error', 'output', 'result', 'exception']) or line.strip() == expected_result:
                            return True

    return False

def is_template_execution(response_text, payload, indicators):
    """Check if template payload was executed based on expected indicators"""
    if not response_text or not indicators:
        return False

    response_lower = response_text.lower()

    # Check if payload is simply reflected
    if payload.lower() in response_lower:
        return False

    # Look for execution indicators
    found_indicators = []
    for indicator in indicators:
        if indicator.lower() in response_lower:
            found_indicators.append(indicator)

    # Need at least one strong indicator
    if found_indicators:
        # Verify it's not generic content by checking context
        for indicator in found_indicators:
            # Look for the indicator in non-HTML contexts
            if check_execution_context(response_text, indicator):
                return True

    return False

def check_execution_context(response_text, indicator):
    """Check if indicator appears in a context suggesting code execution"""
    lines = response_text.split('\n')
    for line in lines:
        if indicator.lower() in line.lower():
            line_clean = line.strip().lower()

            # Skip if it appears in typical HTML/JS/CSS contexts
            if any(skip_pattern in line_clean for skip_pattern in [
                '<script', '<style', '<!--', 'href=', 'src=', 'class=', 'id='
            ]):
                continue

            # Look for execution contexts
            if any(exec_pattern in line_clean for exec_pattern in [
                'class', 'object', 'method', 'function', 'error', 'exception',
                'config', 'debug', 'version', 'system'
            ]):
                return True

    return False

def test_reflection_vs_execution(url, param, session, scanner):
    """Test if template syntax is reflected or executed"""
    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        base = url.split('?', 1)[0]

        # Test with obvious reflection payload first
        reflection_payload = "{{REFLECTION_TEST_12345}}"
        qs[param] = reflection_payload
        query = "&".join(f"{k}={requests.utils.quote(str(v))}" for k, v in qs.items())
        test_url = base + "?" + query

        if scanner._is_denied(test_url):
            return None

        reflection_resp = retry_request(session.get, test_url, timeout=10)
        if reflection_resp and "REFLECTION_TEST_12345" in reflection_resp.text:
            # This parameter reflects input, so we need to be extra careful
            return {"reflects": True, "baseline": reflection_resp}

        return {"reflects": False, "baseline": reflection_resp}

    except Exception:
        return None

def param_test(url, param, session, scanner):
    """Test parameter for SSTI vulnerability with robust validation"""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    base = url.split('?', 1)[0]

    # Check reflection behavior
    reflection_test = test_reflection_vs_execution(url, param, session, scanner)
    if not reflection_test:
        return None

    # Test mathematical expressions (most reliable)
    for test_case in SSTI_MATH_PAYLOADS:
        expr, expected = generate_unique_calculation()
        payload = test_case["template"].format(expr)

        qs[param] = payload
        query = "&".join(f"{k}={requests.utils.quote(str(v))}" for k, v in qs.items())
        test_url = base + "?" + query

        if scanner._is_denied(test_url):
            continue

        try:
            resp = retry_request(session.get, test_url, timeout=15)
            if not resp:
                continue

            if is_mathematical_result(resp.text, expr, expected):
                return {
                    "host": scanner.root,
                    "endpoint": test_url,
                    "vul_type": "Server-Side Template Injection (Confirmed)",
                    "param": param,
                    "payload": payload,
                    "details": f"Mathematical expression {expr} evaluated to {expected}",
                    "request_raw": f"GET {test_url} HTTP/1.1\n",
                    "response_raw": resp.text[:1000],
                    "short_desc": "Confirmed SSTI via mathematical evaluation",
                    "mitigation": "Sanitize user input, use safe template engines",
                    "confidence": "High"
                }

        except Exception:
            pass

        time.sleep(scanner.sleep)

    # Test template-specific payloads if math tests didn't work
    if not reflection_test.get("reflects", False):  # Only if input isn't directly reflected
        for template_test in TEMPLATE_PAYLOADS[:3]:  # Limit to avoid noise
            qs[param] = template_test["payload"]
            query = "&".join(f"{k}={requests.utils.quote(str(v))}" for k, v in qs.items())
            test_url = base + "?" + query

            if scanner._is_denied(test_url):
                continue

            try:
                resp = retry_request(session.get, test_url, timeout=15)
                if not resp:
                    continue

                if is_template_execution(resp.text, template_test["payload"], template_test["indicators"]):
                    return {
                        "host": scanner.root,
                        "endpoint": test_url,
                        "vul_type": "Server-Side Template Injection",
                        "param": param,
                        "payload": template_test["payload"],
                        "details": f"Template execution detected via indicators: {template_test['indicators']}",
                        "request_raw": f"GET {test_url} HTTP/1.1\n",
                        "response_raw": resp.text[:1000],
                        "short_desc": "SSTI vulnerability detected",
                        "mitigation": "Sanitize user input, use safe template engines",
                        "confidence": "Medium"
                    }

            except Exception:
                pass

            time.sleep(scanner.sleep)

    return None

def form_test(form, session, scanner):
    """Test form fields for SSTI with robust validation"""
    for field in list(form.get("inputs", {}).keys())[:3]:
        # Test with mathematical expressions
        expr, expected = generate_unique_calculation()

        for template_format in ["{{{}}}", "${{{}}}", "<%= {} %>"]:
            payload = template_format.format(expr)
            data = {k: (payload if k == field else v) for k, v in form.get("inputs", {}).items()}

            try:
                if form.get("method", "GET").upper() == "POST":
                    resp = retry_request(session.post, form["action"], data=data, timeout=15)
                else:
                    resp = retry_request(session.get, form["action"], params=data, timeout=15)

                if resp and is_mathematical_result(resp.text, expr, expected):
                    return {
                        "host": scanner.root,
                        "endpoint": form["action"],
                        "vul_type": "Server-Side Template Injection (Form)",
                        "param": field,
                        "payload": payload,
                        "details": f"Mathematical expression {expr} evaluated to {expected}",
                        "request_raw": f"FORM {form['action']} DATA: {data}",
                        "response_raw": resp.text[:1000],
                        "short_desc": "SSTI via form input",
                        "mitigation": "Sanitize form inputs",
                        "confidence": "High"
                    }

            except Exception:
                pass

            time.sleep(scanner.sleep)

    return None

def register():
    return {
        "name": "ssti",
        "param_test": param_test,
        "form_test": form_test,
        "description": "Advanced SSTI detection with false positive mitigation"
    }
