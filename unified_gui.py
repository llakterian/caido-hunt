#!/usr/bin/env python3
"""
Unified GUI for Caido Hunt Scanner
=================================
A comprehensive web interface that combines the best features from both GUI approaches.

Features:
- Works with existing scanner structure
- Real-time scan progress tracking
- Interactive web interface
- Multiple export formats
- Live vulnerability updates
- Mobile-responsive design
- Works with both original and fixed scanner

Author: Security Research Team
Version: 4.1 Unified
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
from flask import Flask, render_template_string, jsonify, request, send_file
from flask_socketio import SocketIO, emit
import webbrowser

# Add project paths
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))
sys.path.insert(0, str(current_dir / "caido_hunt"))


class UnifiedScannerGUI:
    def __init__(self, host="127.0.0.1", port=5000):
        self.host = host
        self.port = port

        # Flask and SocketIO setup
        self.app = Flask(__name__)
        self.app.secret_key = "caido_hunt_unified_gui_2025"
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")

        # Scan state
        self.current_scan_process = None
        self.scan_results = []
        self.scan_status = "Ready"
        self.scan_progress = 0
        self.scan_target = ""
        self.scan_config = {}

        # Thread locks
        self.results_lock = threading.Lock()

        self.setup_routes()
        self.setup_socket_events()

    def setup_routes(self):
        """Setup Flask routes"""

        @self.app.route("/")
        def index():
            return render_template_string(self.get_html_template())

        @self.app.route("/api/scan", methods=["POST"])
        def start_scan():
            if self.current_scan_process and self.current_scan_process.poll() is None:
                return jsonify({"error": "Scan already in progress"}), 400

            data = request.get_json()
            target = data.get("target", "").strip()

            if not target:
                return jsonify({"error": "Target URL is required"}), 400

            # Store scan configuration
            self.scan_target = target
            self.scan_config = {
                "threads": int(data.get("threads", 5)),
                "delay": float(data.get("delay", 1.0)),
                "timeout": int(data.get("timeout", 15)),
                "max_depth": int(data.get("max_depth", 2)),
                "max_pages": int(data.get("max_pages", 100)),
            }

            # Clear previous results
            with self.results_lock:
                self.scan_results = []
            self.scan_status = "Initializing..."
            self.scan_progress = 0

            # Emit initial status
            self.socketio.emit(
                "scan_started", {"target": target, "config": self.scan_config}
            )

            # Start scan in background thread
            scan_thread = threading.Thread(target=self.run_scan_process, daemon=True)
            scan_thread.start()

            return jsonify({"success": True, "message": "Scan started successfully"})

        @self.app.route("/api/status")
        def get_status():
            with self.results_lock:
                return jsonify(
                    {
                        "status": self.scan_status,
                        "progress": self.scan_progress,
                        "target": self.scan_target,
                        "results_count": len(self.scan_results),
                        "latest_results": self.scan_results[-5:]
                        if self.scan_results
                        else [],
                    }
                )

        @self.app.route("/api/results")
        def get_all_results():
            with self.results_lock:
                return jsonify(
                    {
                        "results": self.scan_results,
                        "count": len(self.scan_results),
                        "target": self.scan_target,
                    }
                )

        @self.app.route("/export/json")
        def export_json():
            with self.results_lock:
                report_data = {
                    "scan_info": {
                        "target": self.scan_target,
                        "timestamp": datetime.now().isoformat(),
                        "config": self.scan_config,
                    },
                    "summary": {
                        "total_vulnerabilities": len(self.scan_results),
                        "by_severity": self.get_severity_counts(),
                    },
                    "vulnerabilities": self.scan_results,
                }

            json_str = json.dumps(report_data, indent=2)
            output = io.BytesIO(json_str.encode())

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

            # CSV headers
            writer.writerow(
                [
                    "Type",
                    "URL",
                    "Parameter",
                    "Severity",
                    "Confidence",
                    "Payload",
                    "Evidence",
                    "Description",
                    "Timestamp",
                ]
            )

            # CSV data
            with self.results_lock:
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
                            result.get("description", ""),
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

    def setup_socket_events(self):
        """Setup SocketIO events for real-time updates"""

        @self.socketio.on("connect")
        def handle_connect():
            emit(
                "status_update",
                {
                    "status": self.scan_status,
                    "progress": self.scan_progress,
                    "target": self.scan_target,
                    "results_count": len(self.scan_results),
                },
            )

        @self.socketio.on("request_results")
        def handle_request_results():
            with self.results_lock:
                emit("results_update", {"results": self.scan_results})

    def run_scan_process(self):
        """Run the scanner as a subprocess and monitor results"""
        try:
            self.update_scan_status("Looking for scanner...", 5)

            # Find the best scanner to use
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
                self.update_scan_status("Error: No scanner found", 0)
                return

            scanner_name = (
                "Fixed Scanner" if "fixed" in scanner_file else "Original Scanner"
            )
            self.update_scan_status(f"Using {scanner_name}...", 10)

            # Build command
            cmd = [
                "python",
                scanner_file,
                self.scan_target,
                "--threads",
                str(self.scan_config["threads"]),
                "--delay",
                str(self.scan_config["delay"]),
                "--timeout",
                str(self.scan_config["timeout"]),
                "--max-depth",
                str(self.scan_config["max_depth"]),
                "--max-pages",
                str(self.scan_config["max_pages"]),
                "--verbose",
            ]

            self.update_scan_status("Starting scan process...", 15)

            # Start the scanner process
            self.current_scan_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=str(current_dir),
                bufsize=1,
                universal_newlines=True,
            )

            # Monitor the process
            self.monitor_scan_progress()

            # Wait for completion
            stdout, stderr = self.current_scan_process.communicate()

            # Load results from generated files
            self.update_scan_status("Processing results...", 95)
            self.load_scan_results()

            if self.current_scan_process.returncode == 0:
                result_count = len(self.scan_results)
                self.update_scan_status(
                    f"Scan completed! Found {result_count} vulnerabilities", 100
                )
            else:
                self.update_scan_status("Scan completed with warnings", 100)

        except Exception as e:
            self.update_scan_status(f"Error: {str(e)}", 0)
        finally:
            self.current_scan_process = None

    def monitor_scan_progress(self):
        """Monitor scan progress with realistic progress updates"""
        progress_steps = [
            (20, "Initializing scan..."),
            (30, "Discovering endpoints..."),
            (45, "Crawling target..."),
            (60, "Testing for vulnerabilities..."),
            (75, "Analyzing responses..."),
            (90, "Finalizing scan..."),
        ]

        step_index = 0
        start_time = time.time()

        while self.current_scan_process and self.current_scan_process.poll() is None:
            elapsed_time = time.time() - start_time

            # Update progress based on time and steps
            if step_index < len(progress_steps):
                progress, status = progress_steps[step_index]

                # Move to next step after some time or based on elapsed time
                if elapsed_time > (step_index + 1) * 3:  # 3 seconds per step minimum
                    self.update_scan_status(status, progress)
                    step_index += 1

            # Check for new results periodically
            if int(elapsed_time) % 5 == 0:  # Every 5 seconds
                self.load_scan_results()

            time.sleep(1)

    def load_scan_results(self):
        """Load results from generated report files"""
        try:
            # Look for recent report files
            report_files = list(Path(".").glob("scan_report_*.json"))

            if report_files:
                # Get the most recent report
                latest_report = max(report_files, key=lambda x: x.stat().st_mtime)

                with open(latest_report, "r") as f:
                    report_data = json.load(f)

                # Extract vulnerabilities
                if "vulnerabilities" in report_data:
                    new_results = []
                    for vuln in report_data["vulnerabilities"]:
                        new_results.append(
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

                    # Update results if they're different
                    with self.results_lock:
                        if len(new_results) != len(self.scan_results):
                            self.scan_results = new_results

                            # Emit new results to connected clients
                            self.socketio.emit(
                                "results_update",
                                {
                                    "results": self.scan_results,
                                    "count": len(self.scan_results),
                                },
                            )

        except Exception as e:
            print(f"Error loading results: {e}")

    def update_scan_status(self, status, progress):
        """Update scan status and emit to clients"""
        self.scan_status = status
        self.scan_progress = progress

        # Emit status update to all connected clients
        self.socketio.emit(
            "status_update",
            {
                "status": status,
                "progress": progress,
                "target": self.scan_target,
                "results_count": len(self.scan_results),
            },
        )

    def get_severity_counts(self):
        """Get count of vulnerabilities by severity"""
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

        with self.results_lock:
            for result in self.scan_results:
                severity = result.get("severity", "Unknown")
                if severity in counts:
                    counts[severity] += 1

        return counts

    def get_html_template(self):
        """Return the unified HTML template"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Caido Hunt - Unified Scanner GUI</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdn.socket.io/4.7.4/socket.io.min.js"></script>
    <style>
        .severity-Critical { border-left: 6px solid #dc3545; background-color: #f8d7da; }
        .severity-High { border-left: 6px solid #fd7e14; background-color: #fff3cd; }
        .severity-Medium { border-left: 6px solid #ffc107; background-color: #fff3cd; }
        .severity-Low { border-left: 6px solid #28a745; background-color: #d4edda; }
        .hero-gradient { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .pulse { animation: pulse 2s infinite; }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.5; } 100% { opacity: 1; } }
        .stats-card { transition: transform 0.3s ease; cursor: pointer; }
        .stats-card:hover { transform: translateY(-5px); }
        .vulnerability-card { transition: all 0.3s ease; margin-bottom: 1rem; }
        .vulnerability-card:hover { box-shadow: 0 8px 25px rgba(0,0,0,0.15); }
        .status-ready { color: #28a745; }
        .status-scanning { color: #007bff; }
        .status-complete { color: #28a745; }
        .status-error { color: #dc3545; }
        .code-block { background-color: #f8f9fa; border-radius: 4px; padding: 8px; font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace; font-size: 0.85em; white-space: pre-wrap; word-wrap: break-word; }
    </style>
</head>
<body class="bg-light">
    <!-- Header -->
    <div class="hero-gradient text-white py-4">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-md-8">
                    <h1 class="mb-0"><i class="fas fa-shield-alt"></i> Caido Hunt Scanner</h1>
                    <p class="mb-0">Unified Vulnerability Detection Platform</p>
                </div>
                <div class="col-md-4 text-end">
                    <span id="connection-status" class="badge bg-success"><i class="fas fa-wifi"></i> Connected</span>
                </div>
            </div>
        </div>
    </div>

    <div class="container mt-4">
        <!-- Scan Configuration -->
        <div class="row mb-4">
            <div class="col-lg-10 mx-auto">
                <div class="card shadow-sm">
                    <div class="card-header bg-primary text-white">
                        <h5 class="mb-0"><i class="fas fa-cogs"></i> Scan Configuration</h5>
                    </div>
                    <div class="card-body">
                        <form id="scan-form">
                            <div class="row mb-3">
                                <div class="col-md-6">
                                    <label for="target" class="form-label"><i class="fas fa-crosshairs"></i> Target URL</label>
                                    <input type="url" class="form-control" id="target" required placeholder="https://example.com" value="http://example.com">
                                </div>
                                <div class="col-md-2">
                                    <label for="threads" class="form-label"><i class="fas fa-tasks"></i> Threads</label>
                                    <select class="form-select" id="threads">
                                        <option value="1">1 (Safe)</option>
                                        <option value="3">3 (Balanced)</option>
                                        <option value="5" selected>5 (Standard)</option>
                                        <option value="10">10 (Fast)</option>
                                    </select>
                                </div>
                                <div class="col-md-2">
                                    <label for="delay" class="form-label"><i class="fas fa-clock"></i> Delay (s)</label>
                                    <select class="form-select" id="delay">
                                        <option value="0.5">0.5</option>
                                        <option value="1.0" selected>1.0</option>
                                        <option value="2.0">2.0</option>
                                        <option value="3.0">3.0 (Stealth)</option>
                                    </select>
                                </div>
                                <div class="col-md-2">
                                    <label for="max_depth" class="form-label"><i class="fas fa-layer-group"></i> Depth</label>
                                    <select class="form-select" id="max_depth">
                                        <option value="1">1 (Surface)</option>
                                        <option value="2" selected>2 (Standard)</option>
                                        <option value="3">3 (Deep)</option>
                                    </select>
                                </div>
                            </div>
                            <div class="row mb-3">
                                <div class="col-md-3">
                                    <label for="timeout" class="form-label"><i class="fas fa-stopwatch"></i> Timeout (s)</label>
                                    <input type="number" class="form-control" id="timeout" value="15" min="5" max="60">
                                </div>
                                <div class="col-md-3">
                                    <label for="max_pages" class="form-label"><i class="fas fa-file-alt"></i> Max Pages</label>
                                    <select class="form-select" id="max_pages">
                                        <option value="20">20 (Quick)</option>
                                        <option value="50">50 (Fast)</option>
                                        <option value="100" selected>100 (Standard)</option>
                                        <option value="500">500 (Deep)</option>
                                    </select>
                                </div>
                                <div class="col-md-6 d-flex align-items-end">
                                    <button type="submit" class="btn btn-danger btn-lg w-100" id="start-scan-btn">
                                        <i class="fas fa-play"></i> Start Vulnerability Scan
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>

        <!-- Progress Section -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="card shadow-sm">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <h6 class="mb-0"><i class="fas fa-chart-line"></i> Scan Progress</h6>
                            <div>
                                <span id="progress-percentage" class="badge bg-primary me-2">0%</span>
                                <span id="scan-status-badge" class="badge bg-secondary">Ready</span>
                            </div>
                        </div>
                        <div class="progress mb-2" style="height: 12px;">
                            <div class="progress-bar progress-bar-striped" id="progress-bar" style="width: 0%"></div>
                        </div>
                        <small id="status-text" class="text-muted"><i class="fas fa-info-circle"></i> Ready to start scanning</small>
                    </div>
                </div>
            </div>
        </div>

        <!-- Statistics -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card stats-card shadow-sm text-white bg-info">
                    <div class="card-body text-center">
                        <i class="fas fa-bug fa-2x mb-2"></i>
                        <h3 id="total-count">0</h3>
                        <p class="card-text mb-0">Total Findings</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stats-card shadow-sm text-white bg-danger">
                    <div class="card-body text-center">
                        <i class="fas fa-skull fa-2x mb-2"></i>
                        <h3 id="critical-count">0</h3>
                        <p class="card-text mb-0">Critical</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stats-card shadow-sm text-white bg-warning">
                    <div class="card-body text-center">
                        <i class="fas fa-exclamation-triangle fa-2x mb-2"></i>
                        <h3 id="high-count">0</h3>
                        <p class="card-text mb-0">High</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stats-card shadow-sm text-white bg-success">
                    <div class="card-body text-center">
                        <i class="fas fa-info-circle fa-2x mb-2"></i>
                        <h3 id="medium-count">0</h3>
                        <p class="card-text mb-0">Medium</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Export Section -->
        <div class="row mb-4">
            <div class="col-12 text-center">
                <div class="btn-group" role="group">
                    <a href="/export/json" class="btn btn-outline-primary" id="export-json">
                        <i class="fas fa-download"></i> JSON Report
                    </a>
                    <a href="/export/csv" class="btn btn-outline-success" id="export-csv">
                        <i class="fas fa-file-csv"></i> CSV Export
                    </a>
                </div>
            </div>
        </div>

        <!-- Results Section -->
        <div class="row">
            <div class="col-12">
                <div class="card shadow-sm">
                    <div class="card-header bg-dark text-white d-flex justify-content-between align-items-center">
                        <h5 class="mb-0"><i class="fas fa-list"></i> Vulnerability Findings</h5>
                        <span id="results-count-badge" class="badge bg-light text-dark">0 findings</span>
                    </div>
                    <div class="card-body" style="max-height: 600px; overflow-y: auto;">
                        <div id="results-container">
                            <div class="text-center text-muted py-5" id="no-results-message">
                                <i class="fas fa-search fa-4x mb-3"></i>
                                <h5>No vulnerabilities found yet</h5>
                                <p>Start a scan to see security findings appear here in real-time</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Initialize Socket.IO
        const socket = io();
        let isScanning = false;
        let scanResults = [];

        // DOM elements
        const scanForm = document.getElementById('scan-form');
        const startScanBtn = document.getElementById('start-scan-btn');
        const progressBar = document.getElementById('progress-bar');
        const progressPercentage = document.getElementById('progress-percentage');
        const statusText = document.getElementById('status-text');
        const scanStatusBadge = document.getElementById('scan-status-badge');
        const connectionStatus = document.getElementById('connection-status');
        const resultsContainer = document.getElementById('results-container');
        const noResultsMessage = document.getElementById('no-results-message');
        const resultsCountBadge = document.getElementById('results-count-badge');

        // Statistics elements
        const totalCount = document.getElementById('total-count');
        const criticalCount = document.getElementById('critical-count');
        const highCount = document.getElementById('high-count');
        const mediumCount = document.getElementById('medium-count');

        // Socket event handlers
        socket.on('connect', () => {
            connectionStatus.innerHTML = '<i class="fas fa-wifi"></i> Connected';
            connectionStatus.className = 'badge bg-success';
        });

        socket.on('disconnect', () => {
            connectionStatus.innerHTML = '<i class="fas fa-wifi"></i> Disconnected';
            connectionStatus.className = 'badge bg-danger';
        });

        socket.on('scan_started', (data) => {
            isScanning = true;
            updateScanUI();
            clearResults();
        });

        socket.on('status_update', (data) => {
            updateProgress(data.progress);
            updateStatus(data.status);
        });

        socket.on('results_update', (data) => {
            updateResults(data.results);
        });

        // Form submission
        scanForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            if (isScanning) return;

            const formData = {
                target: document.getElementById('target').value.trim(),
                threads: parseInt(document.getElementById('threads').value),
                delay: parseFloat(document.getElementById('delay').value),
                timeout: parseInt(document.getElementById('timeout').value),
                max_depth: parseInt(document.getElementById('max_depth').value),
                max_pages: parseInt(document.getElementById('max_pages').value)
            };

            if (!formData.target) {
                alert('Please enter a target URL');
                return;
            }

            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(formData)
                });

                const result = await response.json();

                if (!response.ok) {
                    alert('Error: ' + result.error);
                }
            } catch (error) {
                alert('Network error: ' + error.message);
            }
        });

        // UI update functions
        function updateScanUI() {
            startScanBtn.disabled = true;
            startScanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
            progressBar.classList.add('progress-bar-animated');
        }

        function resetScanUI() {
            isScanning = false;
            startScanBtn.disabled = false;
            startScanBtn.innerHTML = '<i class="fas fa-play"></i> Start Vulnerability Scan';
            progressBar.classList.remove('progress-bar-animated');
        }

        function updateProgress(progress) {
            progressBar.style.width = progress + '%';
            progressPercentage.textContent = Math.round(progress) + '%';

            if (progress >= 100) {
                resetScanUI();
                scanStatusBadge.className = 'badge bg-success';
                scanStatusBadge.textContent = 'Complete';
            } else if (progress > 0) {
                scanStatusBadge.className = 'badge bg-primary pulse';
                scanStatusBadge.textContent = 'Scanning';
            }
        }

        function updateStatus(status) {
            statusText.innerHTML = '<i class="fas fa-info-circle"></i> ' + status;

            if (status.includes('Error')) {
                scanStatusBadge.className = 'badge bg-danger';
                scanStatusBadge.textContent = 'Error';
                resetScanUI();
            }
        }

        function updateResults(results) {
            scanResults = results || [];

            if (scanResults.length === 0) {
                showNoResults();
                updateStatistics(0, 0, 0, 0);
                return;
            }

            // Hide no results message
            noResultsMessage.style.display = 'none';

            // Clear and rebuild results
            resultsContainer.innerHTML = '';

            let critical = 0, high = 0, medium = 0, low = 0;

            scanResults.forEach((result, index) => {
                addResultCard(result, index);

                // Count by severity
                switch(result.severity) {
                    case 'Critical': critical++; break;
                    case 'High': high++; break;
                    case 'Medium': medium++; break;
                    case 'Low': low++; break;
                }
            });

            updateStatistics(scanResults.length, critical, high, medium);
        }

        function addResultCard(result, index) {
            const severityIcon = {
                'Critical': 'fas fa-skull',
                'High': 'fas fa-exclamation-triangle',
                'Medium': 'fas fa-exclamation-circle',
                'Low': 'fas fa-info-circle'
            }[result.severity] || 'fas fa-bug';

            const severityColor = {
                'Critical': 'danger',
                'High': 'warning',
                'Medium': 'info',
                'Low': 'success'
            }[result.severity] || 'secondary';

            const cardHtml = `
                <div class="vulnerability-card card severity-${result.severity} mb-3">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <div>
                            <i class="${severityIcon} me-2"></i>
                            <strong>${result.type}</strong>
                        </div>
                        <div>
                            <span class="badge bg-${severityColor} me-2">${result.severity}</span>
                            <span class="badge bg-outline-secondary">${result.confidence} Confidence</span>
                        </div>
                    </div>
                    <div class="card-body">
                        <h6 class="card-title">${result.description || result.type + ' vulnerability detected'}</h6>
                        <div class="row mb-2">
                            <div class="col-md-6">
                                <strong><i class="fas fa-link"></i> URL:</strong>
                                <div class="code-block">${escapeHtml(result.url)}</div>
                            </div>
                            <div class="col-md-6">
                                <strong><i class="fas fa-tag"></i> Parameter:</strong>
                                <div class="code-block">${escapeHtml(result.parameter)}</div>
                            </div>
                        </div>
                        <div class="row">
                            <div class="col-md-6">
                                <strong><i class="fas fa-code"></i> Payload:</strong>
                                <div class="code-block">${escapeHtml(result.payload)}</div>
                            </div>
                            <div class="col-md-6">
                                <strong><i class="fas fa-search"></i> Evidence:</strong>
                                <div class="code-block">${escapeHtml(result.evidence)}</div>
                            </div>
                        </div>
                        <small class="text-muted mt-2">
                            <i class="fas fa-clock"></i> ${new Date(result.timestamp).toLocaleString()}
                        </small>
                    </div>
                </div>
            `;

            resultsContainer.insertAdjacentHTML('beforeend', cardHtml);
        }

        function showNoResults() {
            resultsContainer.innerHTML = '';
            noResultsMessage.style.display = 'block';
        }

        function clearResults() {
            scanResults = [];
            showNoResults();
        }

        function updateStatistics(total, critical, high, medium) {
            totalCount.textContent = total;
            criticalCount.textContent = critical;
            highCount.textContent = high;
            mediumCount.textContent = medium;
            resultsCountBadge.textContent = total + ' findings';
        }

        function escapeHtml(unsafe) {
            return (unsafe || '')
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }

        // Initialize
        socket.emit('request_results');
    </script>

    <footer style="background: #2c3e50; color: white; padding: 25px; text-align: center; margin-top: 30px; font-size: 14px; box-shadow: 0 -2px 10px rgba(0,0,0,0.1);">
        <div style="max-width: 1000px; margin: 0 auto;">
            <h4 style="margin: 0 0 15px 0; font-size: 18px; color: #3498db;">Caido Hunt Scanner</h4>
            <p style="margin: 10px 0;">Built with ❤️ by <a href="https://github.com/llakterian" target="_blank" style="color: #3498db; text-decoration: none; font-weight: bold;">Llakterian</a></p>
            <p style="margin: 10px 0;">
                <a href="mailto:llakterian@gmail.com" style="color: #3498db; text-decoration: none; margin: 0 10px;">
                    <i class="fas fa-envelope"></i> llakterian@gmail.com
                </a>
                <span style="color: #7f8c8d;">|</span>
                <a href="https://github.com/llakterian/caido-hunt" target="_blank" style="color: #3498db; text-decoration: none; margin: 0 10px;">
                    <i class="fab fa-github"></i> GitHub Repository
                </a>
                <span style="color: #7f8c8d;">|</span>
                <a href="https://github.com/llakterian/caido-hunt/issues" target="_blank" style="color: #3498db; text-decoration: none; margin: 0 10px;">
                    <i class="fas fa-bug"></i> Report Issues
                </a>
            </p>
            <p style="margin: 15px 0 5px 0; font-size: 12px; color: #95a5a6;">
                <strong>⚠️ Important:</strong> This tool is for authorized security testing only. Always obtain proper permission before scanning any targets.
            </p>
            <p style="margin: 5px 0; font-size: 11px; color: #7f8c8d;">
                Version 2.0 | © 2024 Llakterian | Licensed under MIT License
            </p>
        </div>
    </footer>

</body>
</html>
        """

    def run(self):
        """Run the unified GUI server"""
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║                  CAIDO HUNT UNIFIED GUI                      ║
║                Real-Time Vulnerability Scanner               ║
╠══════════════════════════════════════════════════════════════╣
║  🌐 Server: http://{self.host}:{self.port}                          ║
║  🚀 Features: Real-time scanning with live updates          ║
║  📊 Reports: JSON/CSV export capabilities                   ║
║  🛡️  Detection: Uses fixed scanner when available           ║
║  ⚡ Performance: Multi-threaded with progress tracking      ║
╚══════════════════════════════════════════════════════════════╝
""")

        try:
            # Try to open browser automatically
            import webbrowser

            threading.Timer(
                1.5, lambda: webbrowser.open(f"http://{self.host}:{self.port}")
            ).start()
        except:
            pass

        try:
            self.socketio.run(self.app, host=self.host, port=self.port, debug=False)
        except Exception as e:
            print(f"Error starting server: {e}")
            print("Try running with: python unified_gui.py --port 5001")


def main():
    """Main function to start the unified GUI"""
    import argparse

    parser = argparse.ArgumentParser(description="Caido Hunt Unified Scanner GUI")
    parser.add_argument(
        "--host", default="127.0.0.1", help="Host to bind to (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=5000, help="Port to bind to (default: 5000)"
    )

    args = parser.parse_args()

    print(f"""
🚀 Starting Caido Hunt Unified GUI...

📋 Configuration:
   • Host: {args.host}
   • Port: {args.port}
   • Scanner: Auto-detect (Fixed > Original)
   • Features: Real-time scanning, Live updates, Export capabilities

⚠️  Make sure you have authorization before scanning any targets!
""")

    try:
        gui = UnifiedScannerGUI(host=args.host, port=args.port)
        gui.run()
    except KeyboardInterrupt:
        print("\n👋 Shutting down GUI server...")
    except Exception as e:
        print(f"❌ Error starting GUI: {e}")
        print(f"💡 Try a different port: python unified_gui.py --port 5001")


if __name__ == "__main__":
    main()
