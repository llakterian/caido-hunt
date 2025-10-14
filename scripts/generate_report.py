#!/usr/bin/env python3
import csv
import sys
import os
from datetime import datetime

def generate_html_report(results_dir):
    findings_csv = os.path.join(results_dir, 'findings.csv')
    if not os.path.exists(findings_csv):
        print(f"No findings.csv found in {results_dir}")
        return

    findings = []
    with open(findings_csv, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            findings.append(row)

    # Get scan info from directory name
    dir_name = os.path.basename(results_dir)
    host = dir_name.split('_')[0]

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Caido-Hunt Scan Report - {host}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f4f4f4;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            text-align: center;
        }}
        .summary {{
            margin-bottom: 20px;
            padding: 10px;
            background-color: #e9ecef;
            border-radius: 4px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #f8f9fa;
            font-weight: bold;
        }}
        tr:hover {{
            background-color: #f1f1f1;
        }}
        .severity {{
            font-weight: bold;
        }}
        .severity.High {{
            color: #dc3545;
        }}
        .severity.Medium {{
            color: #ffc107;
        }}
        .severity.Low {{
            color: #28a745;
        }}
        .severity.Info {{
            color: #17a2b8;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Caido-Hunt Scan Report</h1>
        <div class="summary">
            <strong>Target:</strong> {host}<br>
            <strong>Scan Directory:</strong> {results_dir}<br>
            <strong>Total Findings:</strong> {len(findings)}<br>
            <strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </div>

        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Host</th>
                    <th>Endpoint</th>
                    <th>Vulnerability Type</th>
                    <th>Parameter</th>
                    <th>Payload</th>
                    <th>Details</th>
                    <th>Severity</th>
                    <th>Proof of Concept (PoC)</th>
                </tr>
            </thead>
            <tbody>
"""

    # Add Proof of Concept (PoC) generation
    for finding in findings:
        finding['poc'] = generate_poc(finding)

def generate_poc(finding):
    """Generate a Proof of Concept (PoC) for a given finding."""
    poc = f"curl -X {finding['method']} {finding['endpoint']}"
    if finding['param']:
        poc += f" -d '{finding['param']}={finding['payload']}'"
    return poc

    for finding in findings:
        html_content += f"""
                <tr>
                    <td>{finding['timestamp']}</td>
                    <td>{finding['host']}</td>
                    <td><a href="{finding['endpoint']}" target="_blank">{finding['endpoint'][:50]}...</a></td>
                    <td>{finding['vul_type']}</td>
                    <td>{finding['param']}</td>
                    <td>{finding['payload']}</td>
                    <td>{finding['details']}</td>
                    <td class="severity {finding['severity']}">{finding['severity']}</td>
                    <td>{finding['poc']}</td>
                </tr>
"""

    html_content += """
            </tbody>
        </table>
    </div>
</body>
</html>
"""

    report_path = os.path.join(results_dir, 'report.html')
    with open(report_path, 'w') as f:
        f.write(html_content)
    print(f"Report generated: {report_path}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python generate_report.py <results_directory>")
        sys.exit(1)
    results_dir = sys.argv[1]
    generate_html_report(results_dir)