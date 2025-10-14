#!/usr/bin/env python3
"""
gui.py - Real-time web GUI for displaying vulnerabilities found.
"""
import threading
from flask import Flask, render_template_string, jsonify, make_response
from flask_socketio import SocketIO

class GUIManager:
    def __init__(self, host='127.0.0.1', port=5000, debug=False):
        self.findings = []
        self.host = host
        self.port = port
        self.debug = debug
        self.app = Flask(__name__)
        self.socketio = SocketIO(self.app)

        @self.app.route('/')
        def index():
            html = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Caido-Hunt Real-Time Findings</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
                <style>
                    .severity-High { border-left-color: #dc3545; }
                    .severity-Medium { border-left-color: #ffc107; }
                    .severity-Low { border-left-color: #28a745; }
                    .severity-Info { border-left-color: #17a2b8; }
                </style>
            </head>
            <body class="bg-light">
                <div class="container mt-4">
                    <h1 class="text-danger mb-4">Caido-Hunt Real-Time Vulnerabilities</h1>
                    <p class="lead">Findings will appear here in real-time as the scan progresses.</p>
                    <div class="mb-3">
                        <div class="progress">
                            <div class="progress-bar" role="progressbar" style="width: 0%" id="scan-progress"></div>
                        </div>
                        <small id="progress-text">Scan not started</small>
                    </div>
                    <div class="d-flex justify-content-between align-items-center mb-3">
                        <div>
                            <strong>Total Findings: <span id="findings-count">0</span></strong>
                        </div>
                        <div>
                            <button class="btn btn-primary btn-sm me-2" onclick="window.open('/export/json', '_blank')">Export JSON</button>
                            <button class="btn btn-success btn-sm me-2" onclick="window.open('/export/csv', '_blank')">Export CSV</button>
                            <button class="btn btn-warning btn-sm me-2" onclick="window.open('/export/xml', '_blank')">Export XML</button>
                            <button class="btn btn-info btn-sm me-2" onclick="window.open('/export/pdf', '_blank')">Export PDF</button>
                            <button class="btn btn-secondary btn-sm" onclick="window.open('/export/markdown', '_blank')">Export Markdown</button>
                        </div>
                    </div>
                    <div class="row mb-3">
                        <div class="col-md-3">
                            <div class="card text-white bg-danger">
                                <div class="card-body">
                                    <h5 class="card-title">High</h5>
                                    <p class="card-text" id="high-count">0</p>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card text-white bg-warning">
                                <div class="card-body">
                                    <h5 class="card-title">Medium</h5>
                                    <p class="card-text" id="medium-count">0</p>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card text-white bg-info">
                                <div class="card-body">
                                    <h5 class="card-title">Low</h5>
                                    <p class="card-text" id="low-count">0</p>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card text-white bg-secondary">
                                <div class="card-body">
                                    <h5 class="card-title">Info</h5>
                                    <p class="card-text" id="info-count">0</p>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="row mb-3">
                        <div class="col-md-3">
                            <input type="text" id="search-input" class="form-control" placeholder="Search findings...">
                        </div>
                        <div class="col-md-3">
                            <select id="severity-filter" class="form-select">
                                <option value="">All Severities</option>
                                <option value="High">High</option>
                                <option value="Medium">Medium</option>
                                <option value="Low">Low</option>
                                <option value="Info">Info</option>
                            </select>
                        </div>
                        <div class="col-md-3">
                            <select id="vul-type-filter" class="form-select">
                                <option value="">All Vuln Types</option>
                            </select>
                        </div>
                        <div class="col-md-3">
                            <select id="endpoint-filter" class="form-select">
                                <option value="">All Endpoints</option>
                            </select>
                        </div>
                    </div>
                    <div class="row mb-3">
                        <div class="col-md-6">
                            <select id="sort-by" class="form-select">
                                <option value="timestamp">Sort by Timestamp</option>
                                <option value="severity">Sort by Severity</option>
                                <option value="vul_type">Sort by Vuln Type</option>
                            </select>
                        </div>
                        <div class="col-md-6">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="reverse-sort">
                                <label class="form-check-label" for="reverse-sort">
                                    Reverse Sort
                                </label>
                            </div>
                        </div>
                    </div>
                    <div id="findings-list" class="row"></div>
                </div>
                <script src="https://cdn.socket.io/4.0.0/socket.io.min.js"></script>
                <script>
                    var socket = io();
                    var allFindings = [];
                    socket.on('new_finding', function(data) {
                        allFindings.push(data);
                        updateFilters();
                        updateFindings();
                    });
                    socket.on('scan_start', function(data) {
                        document.getElementById('progress-text').textContent = 'Scan started - Crawling pages...';
                        document.getElementById('scan-progress').style.width = '0%';
                    });
                    socket.on('progress', function(data) {
                        var percent = (data.pages / data.max_pages) * 100;
                        document.getElementById('scan-progress').style.width = percent + '%';
                        document.getElementById('progress-text').textContent = 'Crawled ' + data.pages + ' / ' + data.max_pages + ' pages';
                    });
                    socket.on('scan_end', function(data) {
                        document.getElementById('scan-progress').style.width = '100%';
                        document.getElementById('progress-text').textContent = 'Scan completed - ' + data.pages + ' pages crawled, running active tests...';
                    });
                    socket.on('update_ui', function(data) {
                        var message = data.message;
                        var listItem = document.createElement('div');
                        listItem.className = 'alert alert-info';
                        listItem.textContent = message;
                        document.getElementById('findings-list').prepend(listItem);
                    });

                    function updateFilters() {
                        var vulTypeSelect = document.getElementById('vul-type-filter');
                        var endpointSelect = document.getElementById('endpoint-filter');
                        var vulTypes = new Set();
                        var endpoints = new Set();
                        allFindings.forEach(function(data) {
                            if (data.vul_type) vulTypes.add(data.vul_type);
                            if (data.endpoint) endpoints.add(data.endpoint);
                        });
                        vulTypeSelect.innerHTML = '<option value="">All Vuln Types</option>';
                        vulTypes.forEach(function(vt) {
                            var opt = document.createElement('option');
                            opt.value = vt;
                            opt.textContent = vt;
                            vulTypeSelect.appendChild(opt);
                        });
                        endpointSelect.innerHTML = '<option value="">All Endpoints</option>';
                        endpoints.forEach(function(ep) {
                            var opt = document.createElement('option');
                            opt.value = ep;
                            opt.textContent = ep;
                            endpointSelect.appendChild(opt);
                        });
                    }

                    function updateFindings() {
                        var counts = {High: 0, Medium: 0, Low: 0, Info: 0};
                        allFindings.forEach(function(data) {
                            var sev = data.severity || 'Info';
                            if (counts[sev] !== undefined) counts[sev]++;
                        });
                        document.getElementById('findings-count').textContent = allFindings.length;
                        document.getElementById('high-count').textContent = counts.High;
                        document.getElementById('medium-count').textContent = counts.Medium;
                        document.getElementById('low-count').textContent = counts.Low;
                        document.getElementById('info-count').textContent = counts.Info;
                        var searchTerm = document.getElementById('search-input').value.toLowerCase();
                        var severityFilter = document.getElementById('severity-filter').value;
                        var vulTypeFilter = document.getElementById('vul-type-filter').value;
                        var endpointFilter = document.getElementById('endpoint-filter').value;
                        var sortBy = document.getElementById('sort-by').value;
                        var reverseSort = document.getElementById('reverse-sort').checked;
                        var filtered = allFindings.filter(function(data) {
                            return (severityFilter === '' || data.severity === severityFilter) &&
                                   (vulTypeFilter === '' || data.vul_type === vulTypeFilter) &&
                                   (endpointFilter === '' || data.endpoint === endpointFilter) &&
                                   (searchTerm === '' || JSON.stringify(data).toLowerCase().includes(searchTerm));
                        });
                        // Sort
                        filtered.sort(function(a, b) {
                            var valA = a[sortBy] || '';
                            var valB = b[sortBy] || '';
                            if (sortBy === 'severity') {
                                var order = {'High': 4, 'Medium': 3, 'Low': 2, 'Info': 1};
                                valA = order[valA] || 0;
                                valB = order[valB] || 0;
                            }
                            if (valA < valB) return reverseSort ? 1 : -1;
                            if (valA > valB) return reverseSort ? -1 : 1;
                            return 0;
                        });
                        var list = document.getElementById('findings-list');
                        list.innerHTML = '';
                        filtered.forEach(function(data) {
                            var col = document.createElement('div');
                            col.className = 'col-md-6 mb-3';
                            var card = document.createElement('div');
                            card.className = 'card h-100 severity-' + (data.severity || 'Info');
                            card.style.borderLeftWidth = '5px';
                            var body = document.createElement('div');
                            body.className = 'card-body';
                            body.innerHTML = '<h5 class="card-title">' + (data.vul_type || 'Unknown Vulnerability') + '</h5>' +
                                             '<h6 class="card-subtitle mb-2 text-muted">Endpoint: <code>' + (data.endpoint || '') + '</code></h6>' +
                                             '<p class="card-text"><strong>Parameter:</strong> ' + (data.param || 'N/A') + '</p>' +
                                             '<p class="card-text"><strong>Details:</strong> ' + (data.details || '') + '</p>' +
                                             '<small class="text-muted">Severity: ' + (data.severity || 'Info') + ' | Timestamp: ' + (data.timestamp || '') + '</small>';
                            card.appendChild(body);
                            col.appendChild(card);
                            list.appendChild(col);
                        });
                    }

                    document.getElementById('search-input').addEventListener('input', updateFindings);
                    document.getElementById('severity-filter').addEventListener('change', updateFindings);
                    document.getElementById('vul-type-filter').addEventListener('change', updateFindings);
                    document.getElementById('endpoint-filter').addEventListener('change', updateFindings);
                    document.getElementById('sort-by').addEventListener('change', updateFindings);
                    document.getElementById('reverse-sort').addEventListener('change', updateFindings);
                </script>
            </body>
            </html>
            """
            return html

        @self.app.route('/export/json')
        def export_json():
            return jsonify(self.findings)

        @self.app.route('/export/csv')
        def export_csv():
            import csv, io
            output = io.StringIO()
            if self.findings:
                writer = csv.DictWriter(output, fieldnames=self.findings[0].keys())
                writer.writeheader()
                writer.writerows(self.findings)
            response = make_response(output.getvalue())
            response.headers["Content-Disposition"] = "attachment; filename=findings.csv"
            response.headers["Content-type"] = "text/csv"
            return response

        @self.app.route('/export/xml')
        def export_xml():
            import xml.etree.ElementTree as ET
            from xml.dom import minidom
            root = ET.Element("findings")
            for f in self.findings:
                finding = ET.SubElement(root, "finding")
                for k, v in f.items():
                    ET.SubElement(finding, k).text = str(v)
            rough_string = ET.tostring(root, 'utf-8')
            reparsed = minidom.parseString(rough_string)
            response = make_response(reparsed.toprettyxml(indent="  "))
            response.headers["Content-Disposition"] = "attachment; filename=findings.xml"
            response.headers["Content-type"] = "application/xml"
            return response

        @self.app.route('/export/markdown')
        def export_markdown():
            md = "# Caido-Hunt Findings Report\n\n"
            md += f"Total Findings: {len(self.findings)}\n\n"
            for f in self.findings:
                md += f"## {f.get('vul_type', 'Unknown Vulnerability')}\n\n"
                md += f"- **Severity:** {f.get('severity', 'Info')}\n"
                md += f"- **Endpoint:** {f.get('endpoint', '')}\n"
                md += f"- **Parameter:** {f.get('param', 'N/A')}\n"
                md += f"- **Details:** {f.get('details', '')}\n\n"
            response = make_response(md)
            response.headers["Content-Disposition"] = "attachment; filename=findings.md"
            response.headers["Content-type"] = "text/markdown"
            return response

        @self.app.route('/export/pdf')
        def export_pdf():
            # Simple HTML report for PDF export
            html = "<html><body><h1>Caido-Hunt Findings Report</h1>"
            html += f"<p>Total Findings: {len(self.findings)}</p>"
            for f in self.findings:
                html += f"<h2>{f.get('vul_type', 'Unknown')}</h2>"
                html += f"<p>Severity: {f.get('severity')}</p>"
                html += f"<p>Endpoint: {f.get('endpoint')}</p>"
                html += f"<p>Details: {f.get('details')}</p><hr>"
            html += "</body></html>"
            response = make_response(html)
            response.headers["Content-Disposition"] = "attachment; filename=findings.html"
            response.headers["Content-type"] = "text/html"
            return response

        @self.socketio.on('connect')
        def handle_connect():
            # Send existing findings to new connections
            for finding in self.findings:
                self.socketio.emit('new_finding', finding)

        @self.socketio.on('nuclei_scan_start')
        def handle_nuclei_scan_start(data):
            self.findings.append(f"Starting nuclei scan: {data['query']}")
            self.socketio.emit('update_ui', {'message': f"Starting nuclei scan: {data['query']}"})

        @self.socketio.on('nuclei_scan_complete')
        def handle_nuclei_scan_complete(data):
            self.findings.append(f"Completed nuclei scan: {data['query']}")
            self.socketio.emit('update_ui', {'message': f"Completed nuclei scan: {data['query']}"})

        self.thread = threading.Thread(target=self._run_server)
        self.thread.daemon = True
        self.thread.start()

    def _run_server(self):
        self.socketio.run(self.app, host=self.host, port=self.port, debug=self.debug, use_reloader=False, allow_unsafe_werkzeug=True)

    def notify(self, finding):
        self.findings.append(finding)
        self.socketio.emit('new_finding', finding)
