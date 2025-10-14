"""
SSRF module - attempt SSRF probes for internal endpoints (metadata IP) and common internal hosts.
"""
from urllib.parse import urlparse, parse_qs
import requests, time
from utils import retry_request

SSRF_PROBES = ["http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "http://localhost/"]

def param_test(url, param, session, scanner):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    base = url.split('?',1)[0]
    for payload in SSRF_PROBES:
        qs[param] = payload
        query = "&".join(f"{k}={requests.utils.quote(str(v))}" for k,v in qs.items())
        test_url = base + "?" + query
        if scanner._is_denied(test_url): continue
        try:
            r = session.get(test_url, timeout=10)
            body = (r.text or "").lower()
            # Check for internal metadata keywords that indicate successful SSRF
            ssrf_indicators = ["instance-id", "ami-id", "hostname", "local-ipv4", "public-ipv4", "security-groups"]
            if any(indicator in body for indicator in ssrf_indicators):
                return {
                    "host": scanner.root,
                    "endpoint": test_url,
                    "vul_type": "SSRF",
                    "param": param,
                    "payload": payload,
                    "details": "internal metadata returned in response",
                    "request_raw": f"GET {test_url} HTTP/1.1\n",
                    "response_raw": r.text,
                    "short_desc": "Potential SSRF to internal service",
                    "mitigation": "Validate and restrict URLs; use allowlist"
                }
        except Exception:
            pass
        time.sleep(scanner.sleep)
    return None

def form_test(form, session, scanner):
    # similar to param test
    for field in list(form.get("inputs",{}).keys())[:6]:
        for payload in SSRF_PROBES[:3]:
            data = {k:(payload if k==field else v) for k,v in form.get("inputs",{}).items()}
            try:
                if form.get("method","GET").upper()=="POST":
                    r = session.post(form["action"], data=data, timeout=10)
                else:
                    r = session.get(form["action"], params=data, timeout=10)
                body = (r.text or "").lower()
                ssrf_indicators = ["instance-id", "ami-id", "hostname", "local-ipv4", "public-ipv4", "security-groups"]
                if any(indicator in body for indicator in ssrf_indicators):
                    return {
                        "host": scanner.root,
                        "endpoint": form["action"],
                        "vul_type": "SSRF (form)",
                        "param": field,
                        "payload": payload,
                        "details": "internal metadata present",
                        "request_raw": f"FORM {form['action']} DATA: {data}",
                        "response_raw": r.text,
                        "short_desc": "SSRF via form input",
                        "mitigation": "Implement URL validation & allowlist"
                    }
            except Exception:
                pass
            time.sleep(scanner.sleep)
    return None

def register():
    return {"name":"ssrf","param_test":param_test,"form_test":form_test}
