#!/usr/bin/env python3
"""
Caido Hunt - Real-Time GUI with Live Terminal Output
=====================================================

Features:
- Real-time terminal output with color coding
- Live vulnerability discovery notifications
- Actual time tracking and estimates
- No fake progress bars - real progress!
- Clean, modern interface with dark terminal

Author: Llakterian (llakterian@gmail.com)
Repository: https://github.com/llakterian/caido-hunt
Version: 2.0 Real-Time Edition
"""

import os
import sys
import json
import threading
import time
import subprocess
import queue
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, render_template_string, jsonify, request, Response
import webbrowser

# Add project paths
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))


class RealTimeScanner:
    def __init__(self, host="127.0.0.1", port=5000):
        self.host = host
        self.port = port

        # Flask app
        self.app = Flask(__name__)
        self.app.secret_key = "caido_hunt_realtime_gui_2025"

        # Scan state
        self.scan_process = None
        self.scan_results = []
        self.scan_status = "Ready"
        self.scan_target = ""
        self.is_scanning = False

        # Real-time terminal output
        self.terminal_queue = queue.Queue()
        self.log_lines = []
        self.max_log_lines = 1000

        # Time tracking
        self.scan_start_time = None
        self.scan_end_time = None
        self.pages_scanned = 0
        self.total_requests = 0
        self.vulnerabilities_found = 0

        # Statistics
        self.stats = {
            "endpoints_discovered": 0,
            "parameters_tested": 0,
            "forms_found": 0,
            "vulnerabilities": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

        # Attribution
        self.repo_url = "https://github.com/llakterian/caido-hunt"
        self.author = "Llakterian"
        self.author_email = "llakterian@gmail.com"

        self.setup_routes()

    def add_log(self, message, level="info"):
        """Add a log message with timestamp and level"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = {"timestamp": timestamp, "level": level, "message": message}
        self.log_lines.append(log_entry)

        # Keep only last N lines
        if len(self.log_lines) > self.max_log_lines:
            self.log_lines = self.log_lines[-self.max_log_lines :]

        # Add to queue for SSE
        self.terminal_queue.put(log_entry)

    def setup_routes(self):
        """Setup all Flask routes"""

        @self.app.route("/")
        def index():
            return render_template_string(self.get_html_template())

        @self.app.route("/api/scan", methods=["POST"])
        def start_scan():
            try:
                if self.is_scanning:
                    return jsonify({"error": "Scan already in progress"}), 400

                # Get JSON data with error handling
                try:
                    data = request.get_json()
                    if data is None:
                        return jsonify({"error": "Invalid JSON data"}), 400
                except Exception as e:
                    return jsonify({"error": f"JSON parse error: {str(e)}"}), 400

                # Validate required fields
                target = data.get("target", "").strip()
                if not target:
                    return jsonify({"error": "Target URL is required"}), 400

                # Validate target URL format
                if not target.startswith(("http://", "https://")):
                    target = "https://" + target

                # Start scan in background
                scan_thread = threading.Thread(
                    target=self.run_scan, args=(target, data), daemon=True
                )
                scan_thread.start()

                return jsonify(
                    {"success": True, "message": "Scan started", "target": target}
                )
            except Exception as e:
                self.add_log(f"Error starting scan: {str(e)}", "error")
                return jsonify({"error": f"Server error: {str(e)}"}), 500

        @self.app.route("/api/status")
        def get_status():
            elapsed = 0
            if self.scan_start_time:
                if self.scan_end_time:
                    elapsed = (
                        self.scan_end_time - self.scan_start_time
                    ).total_seconds()
                else:
                    elapsed = (datetime.now() - self.scan_start_time).total_seconds()

            return jsonify(
                {
                    "status": self.scan_status,
                    "is_scanning": self.is_scanning,
                    "target": self.scan_target,
                    "elapsed_time": int(elapsed),
                    "pages_scanned": self.pages_scanned,
                    "total_requests": self.total_requests,
                    "vulnerabilities_found": self.vulnerabilities_found,
                    "stats": self.stats,
                    "results": self.scan_results[-5:] if self.scan_results else [],
                }
            )

        @self.app.route("/api/logs")
        def get_logs():
            """Get all log lines"""
            return jsonify({"logs": self.log_lines})

        @self.app.route("/api/stream")
        def stream():
            """Server-Sent Events stream for real-time updates"""

            def event_stream():
                while True:
                    try:
                        # Wait for new log entry
                        log = self.terminal_queue.get(timeout=1)
                        yield f"data: {json.dumps(log)}\n\n"
                    except queue.Empty:
                        # Send heartbeat
                        yield f": heartbeat\n\n"

            return Response(event_stream(), mimetype="text/event-stream")

        @self.app.route("/export/json")
        def export_json():
            from flask import send_file
            import io

            report = {
                "scan_info": {
                    "target": self.scan_target,
                    "start_time": self.scan_start_time.isoformat()
                    if self.scan_start_time
                    else None,
                    "end_time": self.scan_end_time.isoformat()
                    if self.scan_end_time
                    else None,
                    "duration": int(
                        (self.scan_end_time - self.scan_start_time).total_seconds()
                    )
                    if self.scan_end_time and self.scan_start_time
                    else 0,
                },
                "statistics": self.stats,
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

    def run_scan(self, target, config):
        """Run the scanner as a subprocess and monitor output"""
        try:
            self.is_scanning = True
            self.scan_target = target
            self.scan_start_time = datetime.now()
            self.scan_end_time = None
            self.pages_scanned = 0
            self.total_requests = 0
            self.vulnerabilities_found = 0
            self.scan_results = []

            self.add_log("=" * 60, "info")
            self.add_log("🎯 Caido Hunt Scanner Started", "success")
            self.add_log(f"Target: {target}", "info")
            self.add_log(
                f"Time: {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}", "info"
            )
            self.add_log(
                f"Config: threads={config.get('threads', 5)}, delay={config.get('delay', 1.0)}s",
                "info",
            )
            self.add_log("=" * 60, "info")

            # Find scanner
            scanner_options = [
                "ultimate_scanner_challenge.py",
                "caido_hunt/main_scanner_fixed.py",
                "caido_hunt/main_scanner.py",
            ]

            scanner_file = None
            for option in scanner_options:
                if os.path.exists(option):
                    scanner_file = option
                    self.add_log(f"✅ Found scanner: {option}", "success")
                    break

            if not scanner_file:
                self.add_log("❌ ERROR: No scanner found!", "error")
                self.add_log(f"Searched for: {', '.join(scanner_options)}", "error")
                self.scan_status = "Error: No scanner found"
                self.is_scanning = False
                return

            self.add_log(f"📦 Using scanner: {scanner_file}", "info")

            # Build command with proper type conversion
            try:
                threads = int(config.get("threads", 5))
                delay = float(config.get("delay", 1.0))
                timeout = int(config.get("timeout", 30))
            except (ValueError, TypeError) as e:
                self.add_log(f"❌ Invalid config values: {e}", "error")
                self.scan_status = "Error: Invalid configuration"
                self.is_scanning = False
                return

            cmd = [
                "python",
                scanner_file,
                target,
                "--threads",
                str(threads),
                "--delay",
                str(delay),
                "--timeout",
                str(timeout),
                "--verbose",
            ]

            self.add_log(f"Command: {' '.join(cmd)}", "info")

            self.add_log(f"🚀 Launching scanner...", "info")
            self.scan_status = "Initializing..."

            # Start process with error handling
            try:
                self.scan_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    cwd=str(current_dir),
                )
            except Exception as e:
                self.add_log(f"❌ Failed to start scanner: {e}", "error")
                self.scan_status = f"Error: {e}"
                self.is_scanning = False
                return

            self.add_log("✅ Scanner process started", "success")
            self.scan_status = "Scanning..."

            # Monitor output in real-time
            try:
                for line in iter(self.scan_process.stdout.readline, ""):
                    if not line:
                        break

                    line = line.strip()
                    if not line:
                        continue

                    # Parse and categorize output
                    level = "info"

                    # Detect vulnerability
                    if "vulnerability" in line.lower() or "🚨" in line:
                        level = "vuln"
                        self.vulnerabilities_found += 1

                        # Try to extract details
                        if (
                            "XSS" in line
                            or "SQL" in line
                            or "RCE" in line
                            or "LFI" in line
                        ):
                            self.scan_results.append(
                                {
                                    "type": "Unknown",
                                    "url": target,
                                    "timestamp": datetime.now().isoformat(),
                                    "description": line,
                                }
                            )

                            # Update severity stats
                            if "Critical" in line:
                                self.stats["critical"] += 1
                            elif "High" in line:
                                self.stats["high"] += 1
                            elif "Medium" in line:
                                self.stats["medium"] += 1
                            else:
                                self.stats["low"] += 1

                            self.stats["vulnerabilities"] = self.vulnerabilities_found

                    # Detect errors
                    elif (
                        "error" in line.lower()
                        or "failed" in line.lower()
                        or "❌" in line
                    ):
                        level = "error"

                    # Detect warnings
                    elif "warning" in line.lower() or "⚠" in line:
                        level = "warning"

                    # Detect success
                    elif (
                        "✅" in line
                        or "success" in line.lower()
                        or "complete" in line.lower()
                    ):
                        level = "success"

                    # Detect info
                    elif "discovered" in line.lower():
                        level = "info"
                        if "endpoint" in line.lower():
                            self.stats["endpoints_discovered"] += 1
                        elif "form" in line.lower():
                            self.stats["forms_found"] += 1

                    # Track progress
                    if "testing" in line.lower() or "scanning" in line.lower():
                        self.pages_scanned += 1
                        self.total_requests += 1

                    # Add to log
                    self.add_log(line, level)

                    # Update status
                    if "crawling" in line.lower():
                        self.scan_status = "Crawling target..."
                    elif "testing" in line.lower():
                        self.scan_status = "Testing vulnerabilities..."
                    elif "analyzing" in line.lower():
                        self.scan_status = "Analyzing responses..."

            except Exception as e:
                self.add_log(f"❌ Error reading scanner output: {e}", "error")

            # Wait for completion
            try:
                self.scan_process.wait()
            except Exception as e:
                self.add_log(f"❌ Error waiting for process: {e}", "error")

            self.scan_end_time = datetime.now()

            duration = (self.scan_end_time - self.scan_start_time).total_seconds()

            self.add_log("=" * 60, "info")
            if self.scan_process.returncode == 0:
                self.add_log(f"✅ Scan completed successfully!", "success")
                self.scan_status = "Completed"
            else:
                self.add_log(f"⚠️ Scan completed with warnings", "warning")
                self.scan_status = "Completed with warnings"

            self.add_log(f"⏱️ Duration: {int(duration)} seconds", "info")
            self.add_log(f"📊 Pages scanned: {self.pages_scanned}", "info")
            self.add_log(f"🔍 Total requests: {self.total_requests}", "info")
            self.add_log(
                f"🚨 Vulnerabilities found: {self.vulnerabilities_found}",
                "vuln" if self.vulnerabilities_found > 0 else "success",
            )
            self.add_log("=" * 60, "info")

        except Exception as e:
            self.add_log(f"❌ ERROR: {str(e)}", "error")
            self.scan_status = f"Error: {str(e)}"
            self.scan_end_time = datetime.now()

        finally:
            self.is_scanning = False

    def get_html_template(self):
        """Return the HTML template with real-time terminal"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Caido Hunt - Real-Time Scanner</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body { background: #1a1a1a; color: #e0e0e0; }

        .hero-section {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 2rem 0;
        }

        .terminal-container {
            background: #0d1117;
            border: 2px solid #30363d;
            border-radius: 8px;
            padding: 0;
            height: 500px;
            overflow: hidden;
            font-family: 'Courier New', monospace;
            box-shadow: 0 4px 20px rgba(0,0,0,0.5);
        }

        .terminal-header {
            background: #161b22;
            padding: 10px 15px;
            border-bottom: 1px solid #30363d;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .terminal-button {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            display: inline-block;
        }

        .btn-red { background: #ff5f56; }
        .btn-yellow { background: #ffbd2e; }
        .btn-green { background: #27c93f; }

        .terminal-title {
            margin-left: 10px;
            font-size: 13px;
            color: #8b949e;
        }

        .terminal-output {
            height: 450px;
            overflow-y: auto;
            padding: 15px;
            font-size: 13px;
            line-height: 1.5;
        }

        .terminal-output::-webkit-scrollbar {
            width: 10px;
        }

        .terminal-output::-webkit-scrollbar-track {
            background: #0d1117;
        }

        .terminal-output::-webkit-scrollbar-thumb {
            background: #30363d;
            border-radius: 5px;
        }

        .log-line {
            margin: 2px 0;
            padding: 2px 5px;
            border-radius: 3px;
        }

        .log-info { color: #58a6ff; }
        .log-success { color: #3fb950; font-weight: bold; }
        .log-warning { color: #d29922; }
        .log-error { color: #f85149; font-weight: bold; }
        .log-vuln {
            color: #ff4444;
            font-weight: bold;
            background: rgba(255, 68, 68, 0.1);
            padding: 5px;
            border-left: 3px solid #ff4444;
        }

        .timestamp {
            color: #6e7681;
            margin-right: 8px;
        }

        .stats-card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1rem;
        }

        .stat-value {
            font-size: 2rem;
            font-weight: bold;
            color: #58a6ff;
        }

        .stat-label {
            color: #8b949e;
            font-size: 0.9rem;
        }

        .form-control, .form-select {
            background: #0d1117;
            border: 1px solid #30363d;
            color: #e0e0e0;
        }

        .form-control:focus, .form-select:focus {
            background: #0d1117;
            border-color: #58a6ff;
            color: #e0e0e0;
            box-shadow: 0 0 0 0.25rem rgba(88, 166, 255, 0.25);
        }

        .btn-primary {
            background: #238636;
            border-color: #238636;
        }

        .btn-primary:hover {
            background: #2ea043;
            border-color: #2ea043;
        }

        .pulse {
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .vulnerability-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: bold;
            margin: 2px;
        }

        .badge-critical {
            background: #da3633;
            color: white;
        }

        .badge-high {
            background: #d29922;
            color: white;
        }

        .badge-medium {
            background: #bf8700;
            color: white;
        }

        .badge-low {
            background: #238636;
            color: white;
        }

        .card {
            background: #161b22;
            border: 1px solid #30363d;
        }

        .card-header {
            background: #0d1117;
            border-bottom: 1px solid #30363d;
        }
    </style>
</head>
<body>
    <!-- Header -->
    <div class="hero-section text-white">
        <div class="container">
            <h1 class="mb-0"><i class="fas fa-terminal"></i> Caido Hunt - Real-Time Scanner</h1>
            <p class="mb-0">Live Terminal Output & Progress Tracking</p>
        </div>
    </div>

    <div class="container mt-4">
        <!-- Configuration -->
        <div class="row mb-4">
            <div class="col-lg-12">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0"><i class="fas fa-cog"></i> Scan Configuration</h5>
                    </div>
                    <div class="card-body">
                        <form id="scanForm">
                            <div class="row">
                                <div class="col-md-6 mb-3">
                                    <label class="form-label">Target URL</label>
                                    <input type="url" id="target" class="form-control" required
                                           placeholder="https://example.com" value="http://testphp.vulnweb.com">
                                </div>
                                <div class="col-md-2 mb-3">
                                    <label class="form-label">Threads</label>
                                    <select id="threads" class="form-select">
                                        <option value="3">3</option>
                                        <option value="5" selected>5</option>
                                        <option value="10">10</option>
                                    </select>
                                </div>
                                <div class="col-md-2 mb-3">
                                    <label class="form-label">Delay (s)</label>
                                    <select id="delay" class="form-select">
                                        <option value="0.5">0.5</option>
                                        <option value="1.0" selected>1.0</option>
                                        <option value="2.0">2.0</option>
                                    </select>
                                </div>
                                <div class="col-md-2 mb-3">
                                    <label class="form-label">Timeout (s)</label>
                                    <select id="timeout" class="form-select">
                                        <option value="15">15</option>
                                        <option value="30" selected>30</option>
                                        <option value="60">60</option>
                                    </select>
                                </div>
                            </div>
                            <div class="row">
                                <div class="col-12">
                                    <button type="submit" class="btn btn-primary btn-lg" id="startBtn">
                                        <i class="fas fa-play"></i> Start Scan
                                    </button>
                                    <button type="button" class="btn btn-success" id="exportBtn">
                                        <i class="fas fa-download"></i> Export JSON
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>

        <!-- Statistics -->
        <div class="row mb-4" id="statsContainer">
            <div class="col-md-3">
                <div class="stats-card text-center">
                    <div class="stat-value" id="elapsedTime">0s</div>
                    <div class="stat-label">Elapsed Time</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stats-card text-center">
                    <div class="stat-value" id="pagesScanned">0</div>
                    <div class="stat-label">Pages Scanned</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stats-card text-center">
                    <div class="stat-value" id="totalRequests">0</div>
                    <div class="stat-label">Total Requests</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stats-card text-center">
                    <div class="stat-value" id="vulnsFound">0</div>
                    <div class="stat-label">Vulnerabilities</div>
                </div>
            </div>
        </div>

        <!-- Real-Time Terminal -->
        <div class="row mb-4">
            <div class="col-lg-12">
                <div class="terminal-container">
                    <div class="terminal-header">
                        <span class="terminal-button btn-red"></span>
                        <span class="terminal-button btn-yellow"></span>
                        <span class="terminal-button btn-green"></span>
                        <span class="terminal-title">
                            <i class="fas fa-terminal"></i> Live Scanner Output
                        </span>
                        <span class="terminal-title ms-auto" id="statusText">Ready</span>
                    </div>
                    <div class="terminal-output" id="terminalOutput">
                        <div class="log-line log-success">
                            <span class="timestamp">[READY]</span>
                            <span>🎯 Caido Hunt Real-Time Scanner - Ready to scan!</span>
                        </div>
                        <div class="log-line log-info">
                            <span class="timestamp">[INFO]</span>
                            <span>💡 Enter a target URL and click "Start Scan" to begin</span>
                        </div>
                        <div class="log-line log-warning">
                            <span class="timestamp">[WARN]</span>
                            <span>⚠️ Only scan authorized targets!</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Severity Breakdown -->
        <div class="row mb-4" id="severityBreakdown" style="display: none;">
            <div class="col-lg-12">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0"><i class="fas fa-chart-bar"></i> Vulnerability Breakdown</h5>
                    </div>
                    <div class="card-body">
                        <div class="row text-center">
                            <div class="col-md-3">
                                <span class="vulnerability-badge badge-critical">
                                    <i class="fas fa-exclamation-triangle"></i> Critical: <span id="criticalCount">0</span>
                                </span>
                            </div>
                            <div class="col-md-3">
                                <span class="vulnerability-badge badge-high">
                                    <i class="fas fa-exclamation-circle"></i> High: <span id="highCount">0</span>
                                </span>
                            </div>
                            <div class="col-md-3">
                                <span class="vulnerability-badge badge-medium">
                                    <i class="fas fa-exclamation"></i> Medium: <span id="mediumCount">0</span>
                                </span>
                            </div>
                            <div class="col-md-3">
                                <span class="vulnerability-badge badge-low">
                                    <i class="fas fa-info-circle"></i> Low: <span id="lowCount">0</span>
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <footer style="background: #0d1117; color: white; padding: 25px; text-align: center; margin-top: 30px; border-top: 1px solid #30363d;">
        <div style="max-width: 1000px; margin: 0 auto;">
            <h5 style="margin: 0 0 15px 0; color: #58a6ff;">Caido Hunt Scanner</h5>
            <p style="margin: 10px 0;">Built with ❤️ by <a href="https://github.com/llakterian" target="_blank" style="color: #58a6ff; text-decoration: none; font-weight: bold;">Llakterian</a></p>
            <p style="margin: 10px 0;">
                <a href="mailto:llakterian@gmail.com" style="color: #58a6ff; text-decoration: none; margin: 0 10px;">
                    <i class="fas fa-envelope"></i> llakterian@gmail.com
                </a>
                <span style="color: #6e7681;">|</span>
                <a href="https://github.com/llakterian/caido-hunt" target="_blank" style="color: #58a6ff; text-decoration: none; margin: 0 10px;">
                    <i class="fab fa-github"></i> GitHub Repository
                </a>
            </p>
            <p style="margin: 15px 0 5px 0; font-size: 12px; color: #8b949e;">
                <strong>⚠️ Important:</strong> This tool is for authorized security testing only.
            </p>
            <p style="margin: 5px 0; font-size: 11px; color: #6e7681;">
                Version 2.0 | © 2024 Llakterian | Licensed under MIT License
            </p>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        const terminalOutput = document.getElementById('terminalOutput');
        const startBtn = document.getElementById('startBtn');
        const exportBtn = document.getElementById('exportBtn');
        const statusText = document.getElementById('statusText');
        let eventSource = null;
        let updateInterval = null;

        // Start scan
        document.getElementById('scanForm').addEventListener('submit', function(e) {
            e.preventDefault();

            const data = {
                target: document.getElementById('target').value,
                threads: parseInt(document.getElementById('threads').value),
                delay: parseFloat(document.getElementById('delay').value),
                timeout: parseInt(document.getElementById('timeout').value)
            };

            startBtn.disabled = true;
            startBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';

            // Clear terminal
            terminalOutput.innerHTML = '';

            // Start SSE connection
            startSSE();

            // Start scan
            fetch('/api/scan', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(data)
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    addLogLine(data.error, 'error');
                    startBtn.disabled = false;
                    startBtn.innerHTML = '<i class="fas fa-play"></i> Start Scan';
                } else {
                    // Start updating stats
                    startStatusUpdates();
                }
            })
            .catch(error => {
                addLogLine('Error: ' + error, 'error');
                startBtn.disabled = false;
                startBtn.innerHTML = '<i class="fas fa-play"></i> Start Scan';
            });
        });

        // Export results
        exportBtn.addEventListener('click', function() {
            window.location.href = '/export/json';
        });

        // Server-Sent Events for real-time logs
        function startSSE() {
            if (eventSource) {
                eventSource.close();
            }

            eventSource = new EventSource('/api/stream');

            eventSource.onmessage = function(event) {
                const log = JSON.parse(event.data);
                addLogLine(log.message, log.level, log.timestamp
);
            };

            eventSource.onerror = function(error) {
                console.error('SSE Error:', error);
            };
        }

        // Add log line to terminal
        function addLogLine(message, level, timestamp) {
            const line = document.createElement('div');
            line.className = `log-line log-${level}`;

            const ts = document.createElement('span');
            ts.className = 'timestamp';
            ts.textContent = `[${timestamp || new Date().toLocaleTimeString()}]`;

            const msg = document.createElement('span');
            msg.textContent = message;

            line.appendChild(ts);
            line.appendChild(msg);
            terminalOutput.appendChild(line);

            // Auto-scroll
            terminalOutput.scrollTop = terminalOutput.scrollHeight;
        }

        // Update status periodically
        function startStatusUpdates() {
            updateInterval = setInterval(updateStatus, 1000);
        }

        function updateStatus() {
            fetch('/api/status')
                .then(response => response.json())
                .then(data => {
                    // Update stats
                    document.getElementById('elapsedTime').textContent = formatTime(data.elapsed_time);
                    document.getElementById('pagesScanned').textContent = data.pages_scanned;
                    document.getElementById('totalRequests').textContent = data.total_requests;
                    document.getElementById('vulnsFound').textContent = data.vulnerabilities_found;

                    // Update status
                    statusText.textContent = data.status;

                    // Update severity breakdown
                    if (data.stats.vulnerabilities > 0) {
                        document.getElementById('severityBreakdown').style.display = 'block';
                        document.getElementById('criticalCount').textContent = data.stats.critical;
                        document.getElementById('highCount').textContent = data.stats.high;
                        document.getElementById('mediumCount').textContent = data.stats.medium;
                        document.getElementById('lowCount').textContent = data.stats.low;
                    }

                    // Check if scan finished
                    if (!data.is_scanning && startBtn.disabled) {
                        startBtn.disabled = false;
                        startBtn.innerHTML = '<i class="fas fa-play"></i> Start Scan';
                        clearInterval(updateInterval);
                        if (eventSource) {
                            eventSource.close();
                        }
                    }
                })
                .catch(error => console.error('Status update error:', error));
        }

        function formatTime(seconds) {
            if (seconds < 60) {
                return `${seconds}s`;
            }
            const mins = Math.floor(seconds / 60);
            const secs = seconds % 60;
            return `${mins}m ${secs}s`;
        }

        // Load existing logs on page load
        fetch('/api/logs')
            .then(response => response.json())
            .then(data => {
                data.logs.forEach(log => {
                    addLogLine(log.message, log.level, log.timestamp);
                });
            });
    </script>
</body>
</html>
        """

    def run(self):
        """Run the GUI server"""
        print("=" * 60)
        print("🎯 Caido Hunt - Real-Time Scanner GUI")
        print("=" * 60)
        print(f"Starting server on http://{self.host}:{self.port}")
        print("Press Ctrl+C to stop")
        print("=" * 60)

        # Auto-open browser
        try:
            threading.Timer(
                1.5, lambda: webbrowser.open(f"http://{self.host}:{self.port}")
            ).start()
        except:
            pass

        try:
            self.app.run(host=self.host, port=self.port, debug=False, threaded=True)
        except Exception as e:
            print(f"Error: {e}")
            print("Try running with: python realtime_gui.py --port 5001")


def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(description="Caido Hunt Real-Time GUI")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind to")

    args = parser.parse_args()

    print("""
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║       🎯 Caido Hunt - Real-Time Scanner GUI 🎯                ║
║                                                                ║
║               Built by Llakterian                             ║
║           llakterian@gmail.com                                ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
    """)

    try:
        gui = RealTimeScanner(args.host, args.port)
        gui.run()
    except KeyboardInterrupt:
        print("\n\n👋 Shutting down gracefully...")
    except Exception as e:
        print(f"❌ Error starting GUI: {e}")
        print(f"💡 Try a different port: python realtime_gui.py --port 5001")


if __name__ == "__main__":
    main()
