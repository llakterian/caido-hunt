"""
RCE module - tests for Remote Code Execution via command injection.
This module uses advanced detection techniques to minimize false positives.
"""
from urllib.parse import urlparse, parse_qs, urlencode
import requests, time, re, random, string
from utils import retry_request

# More targeted RCE payloads with unique identifiers
RCE_PAYLOADS = [
    {
        "unix": [
            "; echo 'RCE_MARKER_12345'",
            "&& echo 'RCE_MARKER_67890'",
            "| echo 'RCE_MARKER_ABCDE'",
            "`echo 'RCE_MARKER_FGHIJ'`",
            "$(echo 'RCE_MARKER_KLMNO')",
        ],
        "windows": [
            "& echo RCE_MARKER_12345",
            "&& echo RCE_MARKER_67890",
            "| echo RCE_MARKER_ABCDE",
        ]
    }
]

# Mathematical calculation payloads for expression injection
CALC_PAYLOADS = [
    "; expr 31337 + 1337",  # Should return 32674
    "&& expr 12345 \\* 2",   # Should return 24690
    "| python -c 'print(7919*13)'",  # Should return 102947
]

def generate_unique_marker():
    """Generate a unique marker for this test session"""
    return 'RCE_TEST_' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

def test_baseline(url, param, session, scanner):
    """Test baseline response with benign payload"""
    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        base = url.split('?',1)[0]

        # Test with benign payload
        qs[param] = "benign_test_value_123"
        query = "&".join(f"{k}={requests.utils.quote(str(v))}" for k,v in qs.items())
        test_url = base + "?" + query

        baseline_resp = retry_request(session.get, test_url, timeout=10)
        return baseline_resp
    except Exception:
        return None

def validate_command_execution(response_text, marker):
    """Validate that the marker appears in response due to command execution"""
    if not marker or not response_text:
        return False

    response_lower = response_text.lower()
    marker_lower = marker.lower()

    # Check if marker appears in response
    if marker_lower not in response_lower:
        return False

    # Advanced validation: check if marker appears in suspicious contexts
    # Look for markers that appear alone on lines or in error outputs
    lines = response_text.split('\n')
    for line in lines:
        line_clean = line.strip().lower()
        if marker_lower in line_clean:
            # Check if it's not part of URL parameters or HTML attributes
            if not any(prefix in line_clean for prefix in ['url=', 'href=', 'src=', 'action=', 'value=']):
                # Check if it appears in contexts suggesting command execution
                if any(context in line_clean for context in ['error', 'exception', 'output', 'result']):
                    return True
                # Or if it appears standalone
                if line_clean.strip() == marker_lower:
                    return True

    return False

def test_mathematical_expression(url, param, session, scanner):
    """Test for expression injection using mathematical calculations"""
    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        base = url.split('?',1)[0]

        test_cases = [
            {"payload": "; expr 31337 + 1337", "expected": "32674"},
            {"payload": "&& python -c 'print(7919*13)'", "expected": "102947"},
            {"payload": "| echo $((12345*2))", "expected": "24690"},
        ]

        for test_case in test_cases:
            qs[param] = test_case["payload"]
            query = "&".join(f"{k}={requests.utils.quote(str(v))}" for k,v in qs.items())
            test_url = base + "?" + query

            if scanner._is_denied(test_url):
                continue

            resp = retry_request(session.get, test_url, timeout=15)
            if resp and test_case["expected"] in resp.text:
                # Validate this is actual execution, not reflection
                if not is_likely_reflection(resp.text, test_case["payload"]):
                    return {
                        "confirmed": True,
                        "payload": test_case["payload"],
                        "evidence": f"Mathematical expression evaluated: {test_case['expected']}",
                        "response": resp.text
                    }

            time.sleep(scanner.sleep)

    except Exception:
        pass

    return None

def is_likely_reflection(response_text, payload):
    """Check if the payload appears to be simply reflected rather than executed"""
    response_lower = response_text.lower()
    payload_lower = payload.lower()

    # If the exact payload appears in the response, it's likely reflection
    if payload_lower in response_lower:
        return True

    # Check if it appears in typical reflection contexts
    reflection_patterns = [
        r'value=["\'].*?' + re.escape(payload_lower) + r'.*?["\']',
        r'<input[^>]*value=["\'].*?' + re.escape(payload_lower),
        r'url.*?' + re.escape(payload_lower),
        r'href.*?' + re.escape(payload_lower),
    ]

    for pattern in reflection_patterns:
        if re.search(pattern, response_lower, re.IGNORECASE):
            return True

    return False

def param_test(url, param, session, scanner):
    """Test parameter for RCE vulnerability with robust validation"""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    base = url.split('?',1)[0]

    # Get baseline response
    baseline = test_baseline(url, param, session, scanner)
    if not baseline:
        return None

    # Test mathematical expressions first (most reliable)
    math_result = test_mathematical_expression(url, param, session, scanner)
    if math_result:
        return {
            "host": scanner.root,
            "endpoint": url,
            "vul_type": "Remote Code Execution (Confirmed)",
            "param": param,
            "payload": math_result["payload"],
            "details": math_result["evidence"],
            "request_raw": f"GET {url} HTTP/1.1\n",
            "response_raw": math_result["response"][:1000],
            "short_desc": "Confirmed RCE via expression injection",
            "mitigation": "Sanitize inputs and avoid shell execution",
            "confidence": "High"
        }

    # Test with unique markers
    unique_marker = generate_unique_marker()

    for platform in ["unix", "windows"]:
        for payload_template in RCE_PAYLOADS[0][platform]:
            # Replace marker in payload
            payload = payload_template.replace('RCE_MARKER_12345', unique_marker).replace('RCE_MARKER_67890', unique_marker).replace('RCE_MARKER_ABCDE', unique_marker).replace('RCE_MARKER_FGHIJ', unique_marker).replace('RCE_MARKER_KLMNO', unique_marker)

            qs[param] = payload
            query = "&".join(f"{k}={requests.utils.quote(str(v))}" for k,v in qs.items())
            test_url = base + "?" + query

            if scanner._is_denied(test_url):
                continue

            try:
                resp = retry_request(session.get, test_url, timeout=15)
                if not resp:
                    continue

                # Check if our unique marker appears in response
                if validate_command_execution(resp.text, unique_marker):
                    # Verify it's not just URL parameter reflection
                    if not is_likely_reflection(resp.text, payload):
                        # Double-check with a different marker
                        verify_marker = generate_unique_marker()
                        verify_payload = payload.replace(unique_marker, verify_marker)

                        qs[param] = verify_payload
                        verify_query = "&".join(f"{k}={requests.utils.quote(str(v))}" for k,v in qs.items())
                        verify_url = base + "?" + verify_query

                        verify_resp = retry_request(session.get, verify_url, timeout=15)
                        if verify_resp and validate_command_execution(verify_resp.text, verify_marker):
                            return {
                                "host": scanner.root,
                                "endpoint": test_url,
                                "vul_type": "Remote Code Execution (Verified)",
                                "param": param,
                                "payload": payload,
                                "details": f"Command execution confirmed with unique marker: {unique_marker}",
                                "request_raw": f"GET {test_url} HTTP/1.1\n",
                                "response_raw": resp.text[:1000],
                                "short_desc": "Verified RCE vulnerability",
                                "mitigation": "Sanitize inputs and avoid shell execution",
                                "confidence": "High"
                            }

            except Exception:
                pass

            time.sleep(scanner.sleep)

    return None

def form_test(form, session, scanner):
    """Test form fields for RCE with robust validation"""
    for field in list(form.get("inputs",{}).keys())[:6]:
        # Test mathematical expressions first
        test_cases = [
            {"payload": "$(expr 31337 + 1337)", "expected": "32674"},
            {"payload": "`python -c 'print(7919*13)'`", "expected": "102947"},
        ]

        for test_case in test_cases:
            data = {k:(test_case["payload"] if k==field else v) for k,v in form.get("inputs",{}).items()}

            try:
                if form.get("method","GET").upper() == "POST":
                    resp = retry_request(session.post, form["action"], data=data, timeout=15)
                else:
                    resp = retry_request(session.get, form["action"], params=data, timeout=15)

                if resp and test_case["expected"] in resp.text:
                    # Verify it's not reflection
                    if not is_likely_reflection(resp.text, test_case["payload"]):
                        return {
                            "host": scanner.root,
                            "endpoint": form["action"],
                            "vul_type": "Remote Code Execution (Form)",
                            "param": field,
                            "payload": test_case["payload"],
                            "details": f"Mathematical expression evaluated: {test_case['expected']}",
                            "request_raw": f"FORM {form['action']} DATA: {data}",
                            "response_raw": resp.text[:1000],
                            "short_desc": "RCE via form input",
                            "mitigation": "Sanitize form inputs",
                            "confidence": "High"
                        }

            except Exception:
                pass

            time.sleep(scanner.sleep)

    return None

def register():
    return {
        "name": "rce",
        "param_test": param_test,
        "form_test": form_test,
        "description": "Advanced RCE detection with false positive mitigation"
    }
