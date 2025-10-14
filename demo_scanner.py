#!/usr/bin/env python3
"""
Caido Hunt - Ultimate Scanner Demo
=================================
This demo showcases the capabilities of the ultimate bug bounty scanner.

Features demonstrated:
- Endpoint discovery
- Vulnerability detection
- Real-time progress tracking
- Comprehensive reporting
- Multiple scan modes

Author: Security Research Team
Version: 4.0
"""

import os
import sys
import time
import json
import argparse
from datetime import datetime
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

try:
    from caido_hunt.main_scanner import UltimateBugBountyScanner, ScanConfig
    from caido_hunt.core.config import get_config
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Please ensure you're running from the project root directory.")
    sys.exit(1)

class ScannerDemo:
    """Demonstration class for the Ultimate Bug Bounty Scanner"""

    def __init__(self):
        self.demo_targets = [
            {
                'name': 'DVWA (Damn Vulnerable Web Application)',
                'url': 'http://localhost/dvwa',
                'description': 'Local vulnerable web application for testing'
            },
            {
                'name': 'WebGoat',
                'url': 'http://localhost:8080/WebGoat',
                'description': 'OWASP WebGoat vulnerable application'
            },
            {
                'name': 'bWAPP',
                'url': 'http://localhost/bWAPP',
                'description': 'Buggy Web Application'
            },
            {
                'name': 'Mutillidae II',
                'url': 'http://localhost/mutillidae',
                'description': 'OWASP Mutillidae II vulnerable application'
            },
            {
                'name': 'Example Domain (Safe)',
                'url': 'http://example.com',
                'description': 'Safe target for testing discovery features'
            }
        ]

    def print_banner(self):
        """Print the demo banner"""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                    CAIDO HUNT SCANNER DEMO                   ║
║                Ultimate Bug Bounty Scanner v4.0             ║
╠══════════════════════════════════════════════════════════════╣
║  🎯 Advanced Vulnerability Detection                         ║
║  🌐 Smart Endpoint Discovery                                 ║
║  🔍 15+ Vulnerability Types                                  ║
║  📊 Comprehensive Reporting                                  ║
║  ⚡ Multi-threaded Performance                              ║
╚══════════════════════════════════════════════════════════════╝
"""
        print(banner)

    def show_available_targets(self):
        """Display available demo targets"""
        print("\n📋 Available Demo Targets:")
        print("=" * 60)

        for i, target in enumerate(self.demo_targets, 1):
            status = "🟢 Online" if self.check_target_availability(target['url']) else "🔴 Offline"
            print(f"{i}. {target['name']}")
            print(f"   URL: {target['url']}")
            print(f"   Description: {target['description']}")
            print(f"   Status: {status}")
            print()

    def check_target_availability(self, url):
        """Check if target is available (simplified check)"""
        try:
            import requests
            response = requests.get(url, timeout=5, verify=False)
            return response.status_code < 500
        except:
            return False

    def run_quick_demo(self, target_url):
        """Run a quick demonstration scan"""
        print(f"\n🚀 Starting Quick Demo Scan")
        print(f"Target: {target_url}")
        print("=" * 60)

        # Create lightweight configuration for demo
        config = ScanConfig(
            threads=5,
            delay=1.0,
            timeout=10,
            max_depth=2,
            max_pages=50
        )

        try:
            # Initialize scanner
            print("🔧 Initializing scanner...")
            scanner = UltimateBugBountyScanner(target_url, config)

            # Start scanning process
            print("🔍 Discovering endpoints...")
            start_time = time.time()

            endpoints = scanner.discover_endpoints()
            discovery_time = time.time() - start_time

            print(f"✅ Discovery complete: {len(endpoints)} endpoints found in {discovery_time:.2f}s")

            if endpoints:
                print("\n📍 Top discovered endpoints:")
                for i, endpoint in enumerate(list(endpoints)[:10], 1):
                    print(f"   {i}. {endpoint}")
                if len(endpoints) > 10:
                    print(f"   ... and {len(endpoints) - 10} more")

            # Vulnerability scanning
            print(f"\n🛡️ Scanning for vulnerabilities...")
            scan_start = time.time()

            scanner.scan_for_vulnerabilities(endpoints)
            scan_time = time.time() - scan_start

            print(f"✅ Vulnerability scan complete in {scan_time:.2f}s")

            # Generate report
            report = scanner.generate_report()
            self.display_scan_results(report)

            # Save demo report
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_file = f"demo_scan_report_{timestamp}.json"
            scanner.save_report(report_file)
            print(f"\n📄 Full report saved to: {report_file}")

        except Exception as e:
            print(f"❌ Error during scan: {e}")
            return False

        return True

    def run_comprehensive_demo(self, target_url):
        """Run a comprehensive demonstration scan"""
        print(f"\n🚀 Starting Comprehensive Demo Scan")
        print(f"Target: {target_url}")
        print("=" * 60)

        # Create comprehensive configuration
        config = ScanConfig(
            threads=10,
            delay=0.5,
            timeout=15,
            max_depth=3,
            max_pages=200
        )

        try:
            scanner = UltimateBugBountyScanner(target_url, config)

            print("🔧 Initializing comprehensive scanner...")
            print(f"   Threads: {config.threads}")
            print(f"   Delay: {config.delay}s")
            print(f"   Max depth: {config.max_depth}")
            print(f"   Max pages: {config.max_pages}")

            # Full scan workflow
            total_start = time.time()

            # Discovery phase
            print("\n🔍 Phase 1: Endpoint Discovery")
            endpoints = scanner.discover_endpoints()

            print(f"   ✅ Found {len(endpoints)} endpoints")
            if scanner.tech_stack:
                print(f"   🔧 Detected technologies: {', '.join(scanner.tech_stack)}")

            # Vulnerability detection phase
            print(f"\n🛡️ Phase 2: Vulnerability Detection")
            print("   Testing for:")
            vuln_types = [
                "Cross-Site Scripting (XSS)",
                "SQL Injection",
                "Remote Code Execution (RCE)",
                "Local File Inclusion (LFI)",
                "Server-Side Template Injection (SSTI)",
                "Server-Side Request Forgery (SSRF)",
                "Open Redirect",
                "Header Injection"
            ]

            for vuln_type in vuln_types:
                print(f"   • {vuln_type}")

            scanner.scan_for_vulnerabilities(endpoints)

            total_time = time.time() - total_start
            print(f"\n✅ Comprehensive scan complete in {total_time:.2f}s")

            # Generate and display report
            report = scanner.generate_report()
            self.display_comprehensive_results(report)

            # Save report
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_file = f"comprehensive_demo_report_{timestamp}.json"
            scanner.save_report(report_file)
            print(f"\n📄 Comprehensive report saved to: {report_file}")

        except Exception as e:
            print(f"❌ Error during comprehensive scan: {e}")
            return False

        return True

    def display_scan_results(self, report):
        """Display basic scan results"""
        print(f"\n📊 SCAN RESULTS SUMMARY")
        print("=" * 40)
        print(f"🎯 Target: {report['target']}")
        print(f"📅 Scan Time: {report['scan_timestamp']}")
        print(f"🌐 Endpoints Discovered: {report['endpoints_discovered']}")
        print(f"🛡️ Total Vulnerabilities: {report['total_vulnerabilities']}")

        if report['total_vulnerabilities'] > 0:
            print(f"\n🚨 Vulnerabilities by Severity:")
            for severity, count in report['vulnerabilities_by_severity'].items():
                if count > 0:
                    emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(severity, "⚪")
                    print(f"   {emoji} {severity}: {count}")

            print(f"\n🔍 Vulnerabilities by Type:")
            for vuln_type, count in report['vulnerabilities_by_type'].items():
                print(f"   • {vuln_type}: {count}")

            print(f"\n🎯 Sample Vulnerabilities:")
            for i, vuln in enumerate(report['vulnerabilities'][:3], 1):
                print(f"   {i}. {vuln['type']} in '{vuln['parameter']}' ({vuln['severity']})")
        else:
            print("✅ No vulnerabilities detected in this quick scan")

    def display_comprehensive_results(self, report):
        """Display comprehensive scan results"""
        print(f"\n📊 COMPREHENSIVE SCAN RESULTS")
        print("=" * 50)
        print(f"🎯 Target: {report['target']}")
        print(f"📅 Scan Timestamp: {report['scan_timestamp']}")
        print(f"🌐 Endpoints Discovered: {report['endpoints_discovered']}")
        print(f"🛡️ Total Vulnerabilities Found: {report['total_vulnerabilities']}")

        if report.get('tech_stack'):
            print(f"🔧 Technology Stack: {', '.join(report['tech_stack'])}")

        if report['total_vulnerabilities'] > 0:
            print(f"\n🚨 SECURITY FINDINGS")
            print("-" * 30)

            print(f"📈 Severity Distribution:")
            for severity, count in report['vulnerabilities_by_severity'].items():
                if count > 0:
                    emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(severity, "⚪")
                    bar = "█" * min(count, 20)
                    print(f"   {emoji} {severity:8}: {count:3} {bar}")

            print(f"\n🔍 Vulnerability Categories:")
            for vuln_type, count in sorted(report['vulnerabilities_by_type'].items()):
                print(f"   • {vuln_type}: {count}")

            print(f"\n🎯 Top 5 Critical Findings:")
            critical_vulns = [v for v in report['vulnerabilities'] if v['severity'] in ['Critical', 'High']]

            for i, vuln in enumerate(critical_vulns[:5], 1):
                print(f"   {i}. {vuln['type']}")
                print(f"      Parameter: {vuln['parameter']}")
                print(f"      Severity: {vuln['severity']}")
                print(f"      URL: {vuln['url']}")
                print()
        else:
            print("✅ No vulnerabilities detected in this scan")
            print("   This could indicate:")
            print("   • Well-secured application")
            print("   • Limited attack surface")
            print("   • Need for authenticated scanning")

    def run_interactive_demo(self):
        """Run interactive demo mode"""
        self.print_banner()

        while True:
            print("\n🎮 DEMO MODE SELECTION")
            print("=" * 30)
            print("1. Quick Demo Scan (Fast, limited scope)")
            print("2. Comprehensive Demo (Full features)")
            print("3. Show Available Targets")
            print("4. Custom Target Scan")
            print("5. Exit Demo")

            choice = input("\nSelect option (1-5): ").strip()

            if choice == '1':
                self.show_available_targets()
                target_choice = input("\nSelect target number (1-5) or enter custom URL: ").strip()

                if target_choice.isdigit() and 1 <= int(target_choice) <= 5:
                    target_url = self.demo_targets[int(target_choice) - 1]['url']
                else:
                    target_url = target_choice

                self.run_quick_demo(target_url)

            elif choice == '2':
                self.show_available_targets()
                target_choice = input("\nSelect target number (1-5) or enter custom URL: ").strip()

                if target_choice.isdigit() and 1 <= int(target_choice) <= 5:
                    target_url = self.demo_targets[int(target_choice) - 1]['url']
                else:
                    target_url = target_choice

                print("\n⚠️  WARNING: Comprehensive scan may take several minutes")
                confirm = input("Continue? (y/N): ").strip().lower()
                if confirm == 'y':
                    self.run_comprehensive_demo(target_url)

            elif choice == '3':
                self.show_available_targets()

            elif choice == '4':
                target_url = input("Enter target URL: ").strip()
                scan_type = input("Scan type (quick/comprehensive): ").strip().lower()

                if scan_type == 'comprehensive':
                    self.run_comprehensive_demo(target_url)
                else:
                    self.run_quick_demo(target_url)

            elif choice == '5':
                print("\n👋 Thanks for trying Caido Hunt Scanner!")
                break

            else:
                print("❌ Invalid choice. Please select 1-5.")

    def show_capabilities(self):
        """Show scanner capabilities"""
        print("\n🔥 CAIDO HUNT SCANNER CAPABILITIES")
        print("=" * 50)

        capabilities = {
            "🎯 Vulnerability Detection": [
                "Cross-Site Scripting (XSS) - Reflected, Stored, DOM",
                "SQL Injection - Error-based, Blind, Time-based",
                "Remote Code Execution (RCE)",
                "Local File Inclusion (LFI)",
                "Server-Side Template Injection (SSTI)",
                "Server-Side Request Forgery (SSRF)",
                "Open Redirect Vulnerabilities",
                "XML External Entity (XXE) Attacks",
                "NoSQL Injection",
                "Header Injection",
                "Command Injection",
                "LDAP Injection",
                "XPath Injection"
            ],
            "🌐 Discovery Features": [
                "Smart endpoint crawling",
                "Directory enumeration",
                "Form detection and analysis",
                "Parameter extraction",
                "Technology stack identification",
                "Subdomain discovery support"
            ],
            "⚡ Performance Features": [
                "Multi-threaded scanning",
                "Configurable request delays",
                "Smart rate limiting",
                "Session management",
                "Request retry logic",
                "Memory-efficient crawling"
            ],
            "📊 Reporting Features": [
                "JSON report generation",
                "Severity classification",
                "Detailed vulnerability descriptions",
                "Proof-of-concept payloads",
                "Remediation recommendations",
                "Executive summaries"
            ]
        }

        for category, items in capabilities.items():
            print(f"\n{category}")
            print("-" * 30)
            for item in items:
                print(f"  • {item}")

def main():
    """Main demo function"""
    parser = argparse.ArgumentParser(description="Caido Hunt Scanner Demo")
    parser.add_argument('--target', help='Target URL for direct scan')
    parser.add_argument('--mode', choices=['quick', 'comprehensive'],
                       default='quick', help='Scan mode')
    parser.add_argument('--interactive', action='store_true',
                       help='Run in interactive mode')
    parser.add_argument('--capabilities', action='store_true',
                       help='Show scanner capabilities')

    args = parser.parse_args()

    demo = ScannerDemo()

    if args.capabilities:
        demo.show_capabilities()
        return

    if args.interactive:
        demo.run_interactive_demo()
        return

    if args.target:
        demo.print_banner()
        if args.mode == 'comprehensive':
            demo.run_comprehensive_demo(args.target)
        else:
            demo.run_quick_demo(args.target)
    else:
        # Default to interactive mode
        demo.run_interactive_demo()

if __name__ == '__main__':
    main()
