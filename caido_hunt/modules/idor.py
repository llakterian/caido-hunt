"""
IDOR module - tests for Insecure Direct Object References.
"""
from urllib.parse import urlparse, parse_qs, urlencode
import requests, time
from utils import retry_request

IDOR_KEYWORDS = ['id', 'user_id', 'account_id', 'profile_id', 'item_id']

def param_test(url, param, session, scanner):
    if not any(kw in param.lower() for kw in IDOR_KEYWORDS):
        return None
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    orig_value = qs.get(param, [""])[0]
    base = url.split('?',1)[0]
    # Get original response
    try:
        orig_r = retry_request(session.get, url, timeout=15)
        orig_text = orig_r.text
    except Exception:
        return None
    # Test with modified value
    test_value = '999' if orig_value.isdigit() else 'test999'
    qs[param] = test_value
    query = "&".join(f"{k}={requests.utils.quote(str(v))}" for k,v in qs.items())
    test_url = base + "?" + query
    if scanner._is_denied(test_url):
        return None
    try:
        r = retry_request(session.get, test_url, timeout=15)
        if r.text != orig_text and r.status_code == 200:
            return {
                "host": scanner.root,
                "endpoint": test_url,
                "vul_type": "Potential IDOR",
                "param": param,
                "payload": test_value,
                "details": "Response differs when changing ID parameter",
                "request_raw": f"GET {test_url} HTTP/1.1\n",
                "response_raw": r.text,
                "short_desc": "Possible Insecure Direct Object Reference",
                "mitigation": "Implement proper access controls and authorization checks"
            }
    except Exception:
        pass
    time.sleep(scanner.sleep)
    return None

def form_test(form, session, scanner):
    # Similar for forms, but IDOR in forms is less common
    return None

def register():
    return {"name":"idor","param_test":param_test,"form_test":form_test}