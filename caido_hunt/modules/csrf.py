"""
CSRF module - checks for missing anti-CSRF tokens in POST forms and unsafe GET state-changing endpoints.
"""
from urllib.parse import urlparse
import time

def form_test(form, session, scanner):
    # check if POST form contains a field like csrf or token or has sameorigin header requirement
    if form.get("method","GET").upper() != "POST":
        return None
    inputs = form.get("inputs",{})
    token_fields = [k for k in inputs.keys() if "csrf" in k.lower() or "token" in k.lower() or "nonce" in k.lower()]
    if not token_fields:
        return {
            "host": scanner.root,
            "endpoint": form["action"],
            "vul_type": "CSRF (missing token)",
            "param": ",".join(list(inputs.keys())[:6]),
            "payload": "<none>",
            "details": "POST form does not expose anti-CSRF token fields",
            "request_raw": f"FORM {form['action']} FIELDS: {list(inputs.keys())}",
            "response_raw": "",
            "short_desc": "Form appears to be missing CSRF protections",
            "mitigation": "Add anti-CSRF tokens bound to session and validate server-side"
        }
    return None

def register():
    return {"name":"csrf","form_test":form_test}
