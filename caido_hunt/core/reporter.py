#!/usr/bin/env python3
"""
reporter.py - generate PoC markdown, CSV & JSON logs, optional ELK push.
"""
import os, csv, json, time, logging
from datetime import datetime
try:
    import openai
except ImportError:
    openai = None

logger = logging.getLogger(__name__)

POC_TEMPLATE_MD = """# Vulnerability Report — {title}

## Description
**Summary:** {short_desc}

**Target (host):** `{host}`

**Endpoint:** `{endpoint}`

**Vulnerability Type:** {vul_type}

## Steps To Reproduce
1. Navigate to the target endpoint: `{endpoint}`
2. Inject the payload `{payload}` into the parameter `{param}` (or form field if applicable)
3. Submit the request
4. Observe the response for {details}

## Proof of Concept (PoC)

### PoC Request (raw)
```
{request_raw}
```

### PoC Response (excerpt)
```
{response_raw}
```

## AI Analysis
{ai_analysis}

## Supporting Material/References
- **Parameter:** {param}
- **Payload:** {payload}
- **Additional Details:** {details}
- **Mitigation:** {mitigation}
"""

POC_TEMPLATE_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Report — {title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #d9534f; }}
        h2 {{ color: #5bc0de; }}
        pre {{ background: #f8f8f8; padding: 10px; border: 1px solid #ddd; overflow-x: auto; }}
        .section {{ margin-bottom: 20px; }}
    </style>
</head>
<body>
    <h1>Vulnerability Report — {title}</h1>
    <div class="section">
        <h2>Description</h2>
        <p><strong>Summary:</strong> {short_desc}</p>
        <p><strong>Target (host):</strong> <code>{host}</code></p>
        <p><strong>Endpoint:</strong> <code>{endpoint}</code></p>
        <p><strong>Vulnerability Type:</strong> {vul_type}</p>
    </div>
    <div class="section">
        <h2>Steps To Reproduce</h2>
        <ol>
            <li>Navigate to the target endpoint: <code>{endpoint}</code></li>
            <li>Inject the payload <code>{payload}</code> into the parameter <code>{param}</code> (or form field if applicable)</li>
            <li>Submit the request</li>
            <li>Observe the response for {details}</li>
        </ol>
    </div>
    <div class="section">
        <h2>Proof of Concept (PoC)</h2>
        <h3>PoC Request (raw)</h3>
        <pre>{request_raw}</pre>
        <h3>PoC Response (excerpt)</h3>
        <pre>{response_raw}</pre>
    </div>
    <div class="section">
        <h2>AI Analysis</h2>
        <p>{ai_analysis}</p>
    </div>
    <div class="section">
        <h2>Supporting Material/References</h2>
        <ul>
            <li><strong>Parameter:</strong> {param}</li>
            <li><strong>Payload:</strong> {payload}</li>
            <li><strong>Additional Details:</strong> {details}</li>
            <li><strong>Mitigation:</strong> {mitigation}</li>
        </ul>
    </div>
</body>
</html>
"""

class Reporter:
    def __init__(self, results_dir, elk_url=None, gui_manager=None, bounty_url=None, ai_api_key=None, filter_high_impact=False):
        self.results_dir = results_dir
        self.elk_url = elk_url
        self.gui_manager = gui_manager
        self.bounty_url = bounty_url
        self.ai_api_key = ai_api_key
        self.filter_high_impact = filter_high_impact
        self.high_impact_types = [
            "Potential RCE (Command Injection)",
            "SQL Injection",
            "Local File Inclusion",
            "Server-Side Request Forgery"
        ]
        self.auth_keywords = ["login", "auth", "password", "session", "account", "user", "admin"]
        self.findings_dir = os.path.join(results_dir, "findings")
        os.makedirs(self.findings_dir, exist_ok=True)
        self.findings_csv = os.path.join(results_dir, "findings.csv")
        self.findings_json = os.path.join(results_dir, "findings.json")
        self._init_csv()
        self.findings = []
        
    def _init_csv(self):
        with open(self.findings_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "host", "endpoint", "vul_type", "param", "payload", "details", "severity"])
            
    def record_finding(self, finding):
        # Filter for high-impact findings if enabled
        if self.filter_high_impact:
            vul_type = finding.get("vul_type", "")
            endpoint = finding.get("endpoint", "").lower()
            if vul_type not in self.high_impact_types:
                if not any(keyword in endpoint for keyword in self.auth_keywords):
                    logger.info(f"Filtered out low-impact finding: {vul_type} at {endpoint}")
                    return  # Skip recording

        # Add timestamp
        finding["timestamp"] = datetime.now().isoformat()
        # Add severity (default High, can be customized by modules)
        if 'severity' not in finding:
            finding['severity'] = 'High'
        
        # Save to CSV
        with open(self.findings_csv, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                finding.get("timestamp"),
                finding.get("host"),
                finding.get("endpoint"),
                finding.get("vul_type"),
                finding.get("param"),
                finding.get("payload"),
                finding.get("details"),
                finding.get("severity")
            ])
            
        # Save to findings list for JSON
        self.findings.append(finding)
        with open(self.findings_json, "w", encoding="utf-8") as f:
            json.dump(self.findings, f, indent=2)
            
        # Generate markdown PoC
        md_file = os.path.join(
            self.findings_dir,
            f"{finding.get('vul_type', 'finding').replace(' ', '_')}_{int(time.time())}.md"
        )
        with open(md_file, "w", encoding="utf-8") as f:
            f.write(POC_TEMPLATE_MD.format(
                title=finding.get("vul_type", "Vulnerability"),
                host=finding.get("host", ""),
                endpoint=finding.get("endpoint", ""),
                vul_type=finding.get("vul_type", ""),
                short_desc=finding.get("short_desc", ""),
                request_raw=finding.get("request_raw", ""),
                response_raw=finding.get("response_raw", "")[:500] + "..." if len(finding.get("response_raw", "")) > 500 else finding.get("response_raw", ""),
                param=finding.get("param", ""),
                payload=finding.get("payload", ""),
                details=finding.get("details", ""),
                mitigation=finding.get("mitigation", ""),
                ai_analysis=finding.get("ai_analysis", "N/A")
            ))
        logger.info(f"Finding recorded: {finding.get('vul_type')} -> {md_file}")

        # Generate HTML PoC
        html_file = os.path.join(
            self.findings_dir,
            f"{finding.get('vul_type', 'finding').replace(' ', '_')}_{int(time.time())}.html"
        )
        with open(html_file, "w", encoding="utf-8") as f:
            f.write(POC_TEMPLATE_HTML.format(
                title=finding.get("vul_type", "Vulnerability"),
                host=finding.get("host", ""),
                endpoint=finding.get("endpoint", ""),
                vul_type=finding.get("vul_type", ""),
                short_desc=finding.get("short_desc", ""),
                request_raw=finding.get("request_raw", ""),
                response_raw=finding.get("response_raw", "")[:500] + "..." if len(finding.get("response_raw", "")) > 500 else finding.get("response_raw", ""),
                param=finding.get("param", ""),
                payload=finding.get("payload", ""),
                details=finding.get("details", ""),
                mitigation=finding.get("mitigation", ""),
                ai_analysis=finding.get("ai_analysis", "N/A")
            ))
        logger.info(f"HTML report generated: {html_file}")

        # AI Analysis
        if openai and self.ai_api_key:
            try:
                openai.api_key = self.ai_api_key
                prompt = f"Analyze this security finding for false positives, suggest additional exploit payloads, and predict related vulnerabilities. Provide a brief analysis. Finding details: {json.dumps(finding, indent=2)}"
                response = openai.ChatCompletion.create(
                    model="gpt-3.5-turbo",
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=300
                )
                ai_text = response.choices[0].message.content.strip()
                finding["ai_analysis"] = ai_text
                # Update JSON
                with open(self.findings_json, "w", encoding="utf-8") as f:
                    json.dump(self.findings, f, indent=2)
                # Update Markdown
                with open(md_file, "a", encoding="utf-8") as f:
                    f.write(f"\n\n## AI Analysis\n{ai_text}\n")
                logger.info("AI analysis added to finding")
            except Exception as e:
                logger.error(f"AI analysis failed: {e}")
                finding["ai_analysis"] = "AI analysis unavailable"

        # Notify GUI if enabled
        if self.gui_manager:
            self.gui_manager.notify(finding)

        # Push to ELK if configured
        if self.elk_url:
            try:
                import requests
                requests.post(self.elk_url, json=finding, timeout=10)
                logger.info(f"Finding pushed to ELK: {self.elk_url}")
            except Exception as e:
                logger.error(f"ELK push failed: {e}")

        # Push to bounty program if configured
        if self.bounty_url:
            try:
                import requests
                requests.post(self.bounty_url, json=finding, timeout=10)
                logger.info(f"Finding submitted to bounty program: {self.bounty_url}")
            except Exception as e:
                logger.error(f"Bounty submission failed: {e}")
