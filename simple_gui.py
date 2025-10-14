#!/usr/bin/env python3
"""
Simple GUI for Caido Hunt Scanner
=================================
A reliable, dependency-light web interface for the Caido Hunt vulnerability scanner.

Features:
- Simple Flask-based web interface
- Real-time scan execution
- Results display and export
- Works with existing scanner files
- No complex dependencies (no SocketIO)

Author: Llakterian (llakterian@gmail.com)
Version: 2.0 Simple GUI
"""

import os
import sys
import json
import threading
import time
import subprocess
import io
import csv
from datetime import datetime
from pathlib import Path
from flask import (
    Flask,
    render_template_string,
    jsonify,
    request,
    send_file,
    redirect,
    url_for,
)
import webbrowser

# Add project paths
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))


class SimpleGUI:
    def __init__(self, host="127.0.0.1", port=5000):
        self.host = host
        self.port = port

        # Flask app
        self.app = Flask(__name__)
        self.app.secret_key = "caido_hunt_simple_gui_2025"

        # Scan state
        self.scan_process = None
        self.scan_results = []
        self.scan_status = "Ready"
        self.scan_progress = 0
        self.scan_target = ""
        self.is_scanning = False

        # Attribution
        self.repo_url = "https://github.com/llakterian/caido-hunt"
        self.author = "Llakterian"
        self.author_email = "llakterian@gmail.com"

        self.setup_routes()

    def setup_routes(self):
        """Setup all Flask routes"""

        @self.app.route("/")
        def index():
            return render_template_string(self.get_html_template())

        @self.app.route("/api/scan", methods=["POST"])
        def start_scan():
            if self.is_scanning:
                return jsonify({"error": "Scan already in progress"}), 400

            data = request.get_json()
            target = data.get("target", "").strip()

            if not target:
                return jsonify({"error": "Target URL is required"}), 400

            # Start scan in background
            scan_thread = threading.Thread(
                target=self.run_scan, args=(target, data), daemon=True
            )
            scan_thread.start()

            return jsonify({"success": True, "message": "Scan started"})

        @self.app.route("/api/status")
        def get_status():
            return jsonify(
                {
                    "status": self.scan_status,
                    "progress": self.scan_progress,
                    "is_scanning": self.is_scanning,
                    "target": self.scan_target,
                    "results": self.scan_results,
                    "results_count": len(self.scan_results),
                }
            )

        @self.app.route("/export/json")
        def export_json():
            report = {
                "scan_info": {
                    "target": self.scan_target,
                    "timestamp": datetime.now().isoformat(),
                },
                "summary": {
                    "total_vulnerabilities": len(self.scan_results),
                    "by_severity": self.get_severity_counts(),
                },
                "vulnerabilities": self.scan_results,
            }

            json_data = json.dumps(report, indent=2)
            output = io.BytesIO(json_data.encode())

            return send_file(
                output,
                mimetype="application/json",
                as_attachment=True,
                download_name=f"caido_hunt_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            )

        @self.app.route("/export/csv")
        def export_csv():
            output = io.StringIO()
            writer = csv.writer(output)

            # Headers
            writer.writerow(
                [
                    "Type",
                    "URL",
                    "Parameter",
                    "Severity",
                    "Confidence",
                    "Payload",
                    "Evidence",
                    "Timestamp",
                ]
            )

            # Data
            for result in self.scan_results:
                writer.writerow(
                    [
                        result.get("type", ""),
                        result.get("url", ""),
                        result.get("parameter", ""),
                        result.get("severity", ""),
                        result.get("confidence", ""),
                        result.get("payload", ""),
                        result.get("evidence", ""),
                        result.get("timestamp", ""),
                    ]
                )

            output.seek(0)
            return send_file(
                io.BytesIO(output.getvalue().encode()),
                mimetype="text/csv",
                as_attachment=True,
                download_name=f"caido_hunt_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            )

    def run_scan(self, target, config):
        """Execute the scan"""
        try:
            self.is_scanning = True
            self.scan_target = target
            self.scan_results = []
            self.scan_status = "Initializing..."
            self.scan_progress = 10

            # Find scanner
            scanner_options = [
                "caido_hunt/main_scanner_fixed.py",
                "caido_hunt/main_scanner.py",
            ]

            scanner_file = None
            for scanner in scanner_options:
                if Path(scanner).exists():
                    scanner_file = scanner
                    break

            if not scanner_file:
                self.scan_status = "Error: No scanner found"
                self.is_scanning = False
                return

            scanner_type = "Fixed" if "fixed" in scanner_file else "Original"
            self.scan_status = f"Using {scanner_type} Scanner..."
            self.scan_progress = 20

            # Build command
            cmd = [
                "python",
                scanner_file,
                target,
                "--threads",
                str(config.get("threads", 5)),
                "--delay",
                str(config.get("delay", 1.0)),
                "--timeout",
                str(config.get("timeout", 15)),
                "--max-depth",
                str(config.get("max_depth", 2)),
                "--max-pages",
                str(config.get("max_pages", 100)),
                "--verbose",
            ]

            self.scan_status = "Starting scan process..."
            self.scan_progress = 30

            # Start process
            self.scan_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=str(current_dir),
            )

            # Monitor progress
            self.monitor_progress()

            # Wait for completion
            stdout, stderr = self.scan_process.communicate()

            # Load results
            self.scan_status = "Loading results..."
            self.scan_progress = 95
            self.load_results()

            # Completion
            result_count = len(self.scan_results)
            self.scan_status = f"Complete! Found {result_count} vulnerabilities"
            self.scan_progress = 100

        except Exception as e:
            self.scan_status = f"Error: {str(e)}"
            self.scan_progress = 0
        finally:
            self.is_scanning = False
            self.scan_process = None

    def monitor_progress(self):
        """Monitor scan progress"""
        progress_steps = [40, 50, 60, 70, 80, 90]
        step_messages = [
            "Discovering endpoints...",
            "Crawling target...",
            "Testing vulnerabilities...",
            "Analyzing responses...",
            "Checking for false positives...",
            "Finalizing scan...",
        ]

        step = 0
        while self.scan_process and self.scan_process.poll() is None:
            if step < len(progress_steps):
                self.scan_progress = progress_steps[step]
                self.scan_status = step_messages[step]
                step += 1

            time.sleep(3)

    def load_results(self):
        """Load scan results from generated files"""
        try:
            # Find latest report
            report_files = list(Path(".").glob("scan_report_*.json"))
            if report_files:
                latest = max(report_files, key=lambda x: x.stat().st_mtime)

                with open(latest, "r") as f:
                    data = json.load(f)

                # Extract vulnerabilities
                self.scan_results = []
                for vuln in data.get("vulnerabilities", []):
                    self.scan_results.append(
                        {
                            "type": vuln.get("type", "Unknown"),
                            "url": vuln.get("url", ""),
                            "parameter": vuln.get("parameter", ""),
                            "severity": vuln.get("severity", "Unknown"),
                            "confidence": vuln.get("confidence", "Unknown"),
                            "payload": vuln.get("payload", ""),
                            "evidence": vuln.get("evidence", ""),
                            "description": vuln.get("description", ""),
                            "timestamp": vuln.get(
                                "timestamp", datetime.now().isoformat()
                            ),
                        }
                    )
        except Exception as e:
            print(f"Error loading results: {e}")

    def get_severity_counts(self):
        """Get vulnerability counts by severity"""
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for result in self.scan_results:
            severity = result.get("severity", "Unknown")
            if severity in counts:
                counts[severity] += 1
        return counts

    def get_html_template(self):
        """Return the HTML template"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Caido Hunt - Simple Scanner GUI</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        .severity-Critical { border-left: 5px solid #dc3545; background-color: #f8d7da; }
        .severity-High { border-left: 5px solid #fd7e14; background-color: #fff3cd; }
        .severity-Medium { border-left: 5px solid #ffc107; background-color: #fff3cd; }
        .severity-Low { border-left: 5px solid #28a745; background-color: #d4edda; }
        .hero-section { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .pulse { animation: pulse 2s infinite; }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.5; } 100% { opacity: 1; } }
        .code-snippet { background: #f8f9fa; padding: 8px; border-radius: 4px; font-family: monospace; font-size: 0.9em; }
        .stats-card { transition: transform 0.3s ease; }
        .stats-card:hover { transform: translateY(-2px); }
    </style>
</head>
<body class="bg-light">
    <!-- Header -->
    <div class="hero-section text-white py-4">
        <div class="container">
            <h1 class="mb-0"><i class="fas fa-shield-alt"></i> Caido Hunt Scanner</h1>
            <p class="mb-0">Simple & Reliable Vulnerability Detection</p>
        </div>
    </div>

    <div class="container mt-4">
        <!-- Scan Form -->
        <div class="row mb-4">
            <div class="col-lg-8 mx-auto">
                <div class="card shadow">
                    <div class="card-header bg-primary text-white">
                        <h5 class="mb-0"><i class="fas fa-crosshairs"></i> Target Configuration</h5>
                    </div>
                    <div class="card-body">
                        <form id="scanForm">
                            <div class="row mb-3">
                                <div class="col-md-8">
                                    <label class="form-label">Target URL</label>
                                    <input type="url" id="target" class="form-control" required
                                           placeholder="https://example.com" value="http://example.com">
                                </div>
                                <div class="col-md-4">
                                    <label class="form-label">Threads</label>
                                    <select id="threads" class="form-select">
                                        <option value="1">1 (Safe)</option>
                                        <option value="3">3 (Balanced)</option>
                                        <option value="5" selected>5 (Standard)</option>
                                        <option value="10">10 (Fast)</option>
                                    </select>
                                </div>
                            </div>
                            <div class="row mb-3">
                                <div class="col-md-3">
                                    <label class="form-label">Delay (s)</label>
                                    <select id="delay" class="form-select">
                                        <option value="0.5">0.5</option>
                                        <option value="1.0" selected>1.0</option>
                                        <option value="2.0">2.0</option>
                                        <option value="3.0">3.0 (Stealth)</option>
                                    </select>
                                </div>
                                <div class="col-md-3">
                                    <label class="form-label">Max Depth</label>
                                    <select id="max_depth" class="form-select">
                                        <option value="1">1 (Surface)</option>
                                        <option value="2" selected>2 (Standard)</option>
                                        <option value="3">3 (Deep)</option>
                                    </select>
                                </div>
                                <div class="col-md-3">
                                    <label class="form-label">Max Pages</label>
                                    <select id="max_pages" class="form-select">
                                        <option value="20">20 (Quick)</option>
                                        <option value="50">50 (Fast)</option>
                                        <option value="100" selected>100 (Standard)</option>
                                        <option value="500">500 (Deep)</option>
                                    </select>
                                </div>
                                <div class="col-md-3 d-flex align-items-end">
                                    <button type="submit" id="scanBtn" class="btn btn-danger w-100">
                                        <i class="fas fa-play"></i> Start Scan
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>

        <!-- Progress -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-body">
                        <div class="d-flex justify-content-between mb-2">
                            <h6>Scan Progress</h6>
                            <span id="progressText" class="badge bg-secondary">Ready</span>
                        </div>
                        <div class="progress mb-2">
                            <div id="progressBar" class="progress-bar" style="width: 0%"></div>
                        </div>
                        <small id="statusText" class="text-muted">Ready to start scanning</small>
                    </div>
                </div>
            </div>
        </div>

        <!-- Stats -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card stats-card text-white bg-info">
                    <div class="card-body text-center">
                        <i class="fas fa-bug fa-2x mb-2"></i>
                        <h3 id="totalCount">0</h3>
                        <p class="mb-0">Total</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stats-card text-white bg-danger">
                    <div class="card-body text-center">
                        <i class="fas fa-skull fa-2x mb-2"></i>
                        <h3 id="criticalCount">0</h3>
                        <p class="mb-0">Critical</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stats-card text-white bg-warning">
                    <div class="card-body text-center">
                        <i class="fas fa-exclamation-triangle fa-2x mb-2"></i>
                        <h3 id="highCount">0</h3>
                        <p class="mb-0">High</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stats-card text-white bg-success">
                    <div class="card-body text-center">
                        <i class="fas fa-info-circle fa-2x mb-2"></i>
                        <h3 id="mediumCount">0</h3>
                        <p class="mb-0">Medium</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Export -->
        <div class="row mb-4">
            <div class="col-12 text-center">
                <div class="btn-group">
                    <a href="/export/json" class="btn btn-outline-primary">
                        <i class="fas fa-download"></i> JSON Report
                    </a>
                    <a href="/export/csv" class="btn btn-outline-success">
                        <i class="fas fa-file-csv"></i> CSV Export
                    </a>
                </div>
            </div>
        </div>

        <!-- Results -->
        <div class="row">
            <div class="col-12">
                <div class="card shadow">
                    <div class="card-header bg-dark text-white">
                        <h5 class="mb-0"><i class="fas fa-list"></i> Scan Results</h5>
                    </div>
                    <div class="card-body" style="max-height: 500px; overflow-y: auto;">
                        <div id="resultsContainer">
                            <div id="noResults" class="text-center text-muted py-4">
                                <i class="fas fa-search fa-3x mb-3"></i>
                                <h5>No vulnerabilities found yet</h5>
                                <p>Start a scan to see results here</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        let statusInterval;
        let isScanning = false;

        // Elements
        const scanForm = document.getElementById('scanForm');
        const scanBtn = document.getElementById('scanBtn');
        const progressBar = document.getElementById('progressBar');
        const progressText = document.getElementById('progressText');
        const statusText = document.getElementById('statusText');
        const resultsContainer = document.getElementById('resultsContainer');
        const noResults = document.getElementById('noResults');
        const totalCount = document.getElementById('totalCount');
        const criticalCount = document.getElementById('criticalCount');
        const highCount = document.getElementById('highCount');
        const mediumCount = document.getElementById('mediumCount');

        // Form submit
        scanForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            if (isScanning) return;

            const formData = {
                target: document.getElementById('target').value,
                threads: parseInt(document.getElementById('threads').value),
                delay: parseFloat(document.getElementById('delay').value),
                timeout: 15,
                max_depth: parseInt(document.getElementById('max_depth').value),
                max_pages: parseInt(document.getElementById('max_pages').value)
            };

            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(formData)
                });

                const result = await response.json();

                if (response.ok) {
                    startMonitoring();
                } else {
                    alert('Error: ' + result.error);
                }
            } catch (error) {
                alert('Network error: ' + error.message);
            }
        });

        function startMonitoring() {
            isScanning = true;
            scanBtn.disabled = true;
            scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
            clearResults();

            statusInterval = setInterval(checkStatus, 1000);
        }

        function stopMonitoring() {
            isScanning = false;
            scanBtn.disabled = false;
            scanBtn.innerHTML = '<i class="fas fa-play"></i> Start Scan';

            if (statusInterval) {
                clearInterval(statusInterval);
            }
        }

        async function checkStatus() {
            try {
                const response = await fetch('/api/status');
                const data = await response.json();

                updateProgress(data.progress);
                updateStatus(data.status);
                updateResults(data.results);

                if (!data.is_scanning) {
                    stopMonitoring();
                }
            } catch (error) {
                console.error('Status check failed:', error);
            }
        }

        function updateProgress(progress) {
            progressBar.style.width = progress + '%';
            progressText.textContent = Math.round(progress) + '%';

            if (progress >= 100) {
                progressText.className = 'badge bg-success';
            } else if (progress > 0) {
                progressText.className = 'badge bg-primary pulse';
            }
        }

        function updateStatus(status) {
            statusText.textContent = status;
        }

        function updateResults(results) {
            if (!results || results.length === 0) {
                showNoResults();
                updateStats(0, 0, 0, 0);
                return;
            }

            clearResults();
            noResults.style.display = 'none';

            let critical = 0, high = 0, medium = 0, low = 0;

            results.forEach(result => {
                addResultCard(result);

                switch(result.severity) {
                    case 'Critical': critical++; break;
                    case 'High': high++; break;
                    case 'Medium': medium++; break;
                    case 'Low': low++; break;
                }
            });

            updateStats(results.length, critical, high, medium);
        }

        function addResultCard(result) {
            const severityIcon = {
                'Critical': 'fas fa-skull',
                'High': 'fas fa-exclamation-triangle',
                'Medium': 'fas fa-exclamation-circle',
                'Low': 'fas fa-info-circle'
            }[result.severity] || 'fas fa-bug';

            const card = document.createElement('div');
            card.className = `card severity-${result.severity} mb-3`;
            card.innerHTML = `
                <div class="card-header d-flex justify-content-between">
                    <div>
                        <i class="${severityIcon}"></i>
                        <strong>${result.type}</strong>
                    </div>
                    <span class="badge bg-${result.severity === 'Critical' ? 'danger' :
                                         result.severity === 'High' ? 'warning' :
                                         result.severity === 'Medium' ? 'info' : 'success'}">
                        ${result.severity}
                    </span>
                </div>
                <div class="card-body">
                    <h6>${result.description || result.type + ' vulnerability'}</h6>
                    <p><strong>URL:</strong> <code>${escapeHtml(result.url)}</code></p>
                    <p><strong>Parameter:</strong> <code>${escapeHtml(result.parameter)}</code></p>
                    <div class="row">
                        <div class="col-md-6">
                            <strong>Payload:</strong>
                            <div class="code-snippet">${escapeHtml(result.payload)}</div>
                        </div>
                        <div class="col-md-6">
                            <strong>Evidence:</strong>
                            <div class="code-snippet">${escapeHtml(result.evidence)}</div>
                        </div>
                    </div>
                    <small class="text-muted">
                        <i class="fas fa-clock"></i> ${new Date(result.timestamp).toLocaleString()}
                    </small>
                </div>
            `;
            resultsContainer.appendChild(card);
        }

        function showNoResults() {
            noResults.style.display = 'block';
        }

        function clearResults() {
            Array.from(resultsContainer.children).forEach(child => {
                if (child.id !== 'noResults') {
                    child.remove();
                }
            });
        }

        function updateStats(total, critical, high, medium) {
            totalCount.textContent = total;
            criticalCount.textContent = critical;
            highCount.textContent = high;
            mediumCount.textContent = medium;
        }

        function escapeHtml(unsafe) {
            return (unsafe || '')
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }
    </script>

    <footer style="background: #333; color: white; padding: 20px; text-align: center; margin-top: 20px; font-size: 14px;">
        <p>Caido Hunt Scanner &copy; 2024 - Built by <a href="https://github.com/llakterian" style="color: #4CAF50; text-decoration: none;">Llakterian</a> | <a href="mailto:llakterian@gmail.com" style="color: #4CAF50; text-decoration: none;">llakterian@gmail.com</a></p>
        <p><small>Repository: <a href="https://github.com/llakterian/caido-hunt" style="color: #4CAF50; text-decoration: none;">github.com/llakterian/caido-hunt</a> | <a href="https://github.com/llakterian/caido-hunt/issues" style="color: #4CAF50; text-decoration: none;">Report Issues</a></small></p>
        <p><small>This tool is for authorized security testing only. Always obtain permission before scanning.</small></p>
    </footer>

    </body>
</html>
        """

    def run(self):
        """Run the GUI server"""
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║                CAIDO HUNT SIMPLE GUI                         ║
║              Reliable Vulnerability Scanner                  ║
╠══════════════════════════════════════════════════════════════╣
║  🌐 URL: http://{self.host}:{self.port}                             ║
║  🚀 Features: Simple & Fast scanning interface              ║
║  📊 Exports: JSON and CSV reports                          ║
║  🛡️  Scanner: Auto-detects fixed/original versions          ║
╚══════════════════════════════════════════════════════════════╝
        """)

        # Auto-open browser
        try:
            threading.Timer(
                1.0, lambda: webbrowser.open(f"http://{self.host}:{self.port}")
            ).start()
        except:
            pass

        # Run Flask
        try:
            self.app.run(host=self.host, port=self.port, debug=False, threaded=True)
        except Exception as e:
            print(f"Error: {e}")
            print("Try running with a different port: python simple_gui.py --port 5001")


def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(description="Caido Hunt Simple GUI")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind to")

    args = parser.parse_args()

    print("🚀 Starting Caido Hunt Simple GUI...")
    print("⚠️  Only scan targets you have authorization to test!")
    print()

    try:
        gui = SimpleGUI(host=args.host, port=args.port)
        gui.run()
    except KeyboardInterrupt:
        print("\n👋 GUI stopped by user")
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    main()
