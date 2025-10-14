#!/usr/bin/env python3
"""
hunt.py - Enhanced CLI launcher for plugin-style caido-hunt scanner.
"""
import argparse
import logging
import subprocess
import json
import os
import sys
import time
import signal
from pathlib import Path
from scanner_core import ScannerCore
from config import get_config, reload_config
from health_check import HealthChecker
from utils import validate_url

# Configure logging
def setup_logging(level=logging.INFO, log_file=None):
    """Setup enhanced logging configuration"""
    format_str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    if log_file:
        logging.basicConfig(
            level=level,
            format=format_str,
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
    else:
        logging.basicConfig(level=level, format=format_str)

    # Suppress noisy third-party loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("selenium").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

def run_zap_scan(target, results_dir, config):
    """Enhanced OWASP ZAP integration with configuration support"""
    logger.info("Running OWASP ZAP scan...")

    if not config.get('integrations.zap.enabled'):
        logger.warning("ZAP integration is disabled in configuration")
        return False

    try:
        from zapv2 import ZAPv2

        api_key = config.get('integrations.zap.api_key', 'your-api-key')
        host = config.get('integrations.zap.host', '127.0.0.1')
        port = config.get('integrations.zap.port', 8090)

        if api_key == 'your-api-key':
            logger.error("ZAP API key not configured. Please set integrations.zap.api_key")
            return False

        proxy_url = f"http://{host}:{port}"
        zap = ZAPv2(apikey=api_key, proxies={'http': proxy_url, 'https': proxy_url})

        # Check if ZAP is already running
        try:
            zap.core.version
        except Exception:
            logger.info("Starting ZAP daemon...")
            zap_cmd = ["/usr/share/zaproxy/zap.sh", "-daemon", "-port", str(port), "-config", f"api.key={api_key}"]
            subprocess.Popen(zap_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(15)  # Wait for ZAP to start

            # Verify ZAP is running
            try:
                zap.core.version
                logger.info("ZAP daemon started successfully")
            except Exception as e:
                logger.error(f"Failed to start ZAP daemon: {e}")
                return False

        # Perform scan
        logger.info(f"Starting ZAP spider scan for {target}")
        zap.urlopen(target)
        scan_id = zap.spider.scan(target)

        while int(zap.spider.status(scan_id)) < 100:
            progress = zap.spider.status(scan_id)
            logger.info(f"ZAP spider progress: {progress}%")
            time.sleep(5)

        logger.info("Starting ZAP active scan...")
        ascan_id = zap.ascan.scan(target)

        while int(zap.ascan.status(ascan_id)) < 100:
            progress = zap.ascan.status(ascan_id)
            logger.info(f"ZAP active scan progress: {progress}%")
            time.sleep(10)

        # Generate reports
        alerts = zap.core.alerts()
        zap_output = os.path.join(results_dir, "zap_alerts.json")
        with open(zap_output, "w") as f:
            json.dump(alerts, f, indent=2)

        # Generate HTML report
        html_report = zap.core.htmlreport()
        html_output = os.path.join(results_dir, "zap_report.html")
        with open(html_output, "w") as f:
            f.write(html_report)

        logger.info(f"ZAP scan completed. {len(alerts)} alerts found")
        logger.info(f"Results saved to {zap_output} and {html_output}")
        return True

    except ImportError:
        logger.error("python-owasp-zap-v2.4 not installed. Run: pip install python-owasp-zap-v2.4")
        return False
    except Exception as e:
        logger.error(f"ZAP scan failed: {e}")
        return False

def run_sqlmap_on_findings(results_dir, config):
    """Enhanced SQLmap integration with configuration support"""
    if not config.get('integrations.sqlmap.enabled'):
        logger.warning("SQLmap integration is disabled in configuration")
        return False

    findings_json = os.path.join(results_dir, "findings.json")
    if not os.path.exists(findings_json):
        logger.info("No findings.json found for sqlmap analysis")
        return False

    try:
        with open(findings_json, "r") as f:
            findings = json.load(f)

        sqli_findings = [f for f in findings if "sqli" in f.get("vul_type", "").lower() or "sql injection" in f.get("vul_type", "").lower()]

        if not sqli_findings:
            logger.info("No SQL injection findings for sqlmap analysis")
            return True

        logger.info(f"Found {len(sqli_findings)} SQL injection findings for sqlmap analysis")

        sqlmap_results = []
        timeout = config.get('integrations.sqlmap.timeout', 300)
        batch_mode = config.get('integrations.sqlmap.batch_mode', True)

        for finding in sqli_findings:
            url = finding.get("endpoint")
            param = finding.get("param")

            if not url or not param:
                logger.warning(f"Skipping finding with missing URL or parameter: {finding}")
                continue

            logger.info(f"Running sqlmap on {url} parameter '{param}'")

            cmd = ["sqlmap", "-u", url]

            # Add parameter specification
            if finding.get("method", "GET").upper() == "POST":
                cmd.extend(["--data", f"{param}=*"])
            else:
                cmd.extend(["-p", param])

            if batch_mode:
                cmd.append("--batch")

            cmd.extend(["--dbs", "--timeout", "30", "--retries", "1"])

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

                result_data = {
                    "url": url,
                    "param": param,
                    "command": " ".join(cmd),
                    "return_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "success": result.returncode == 0
                }

                sqlmap_results.append(result_data)

                if result.returncode == 0:
                    logger.info(f"sqlmap completed successfully for {url}")
                else:
                    logger.warning(f"sqlmap failed for {url} with return code {result.returncode}")

            except subprocess.TimeoutExpired:
                logger.error(f"sqlmap timed out for {url} after {timeout} seconds")
                sqlmap_results.append({
                    "url": url,
                    "param": param,
                    "error": f"Timeout after {timeout} seconds",
                    "success": False
                })
            except FileNotFoundError:
                logger.error("sqlmap not installed. Please install sqlmap.")
                return False
            except Exception as e:
                logger.error(f"sqlmap execution error for {url}: {e}")
                sqlmap_results.append({
                    "url": url,
                    "param": param,
                    "error": str(e),
                    "success": False
                })

        # Save sqlmap results
        sqlmap_output = os.path.join(results_dir, "sqlmap_results.json")
        with open(sqlmap_output, "w") as f:
            json.dump(sqlmap_results, f, indent=2)

        successful_tests = sum(1 for r in sqlmap_results if r.get("success"))
        logger.info(f"SQLmap analysis completed: {successful_tests}/{len(sqlmap_results)} tests successful")
        logger.info(f"Results saved to {sqlmap_output}")
        return True

    except Exception as e:
        logger.error(f"SQLmap integration failed: {e}")
        return False

def run_gobuster(target, results_dir, config):
    """Enhanced Gobuster integration with configuration support"""
    if not config.get('integrations.gobuster.enabled'):
        logger.warning("Gobuster integration is disabled in configuration")
        return False

    logger.info("Running gobuster directory enumeration...")

    wordlist = config.get('integrations.gobuster.wordlist', '/usr/share/wordlists/dirb/common.txt')
    timeout = config.get('integrations.gobuster.timeout', 300)

    # Check if wordlist exists
    if not os.path.exists(wordlist):
        # Try alternative wordlist locations
        alternative_wordlists = [
            '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
            '/usr/share/seclists/Discovery/Web-Content/common.txt',
            './wordlists/common.txt'
        ]

        wordlist_found = False
        for alt_wordlist in alternative_wordlists:
            if os.path.exists(alt_wordlist):
                wordlist = alt_wordlist
                wordlist_found = True
                logger.info(f"Using alternative wordlist: {wordlist}")
                break

        if not wordlist_found:
            logger.error(f"No wordlist found. Please install wordlists or specify custom path.")
            return False

    output = os.path.join(results_dir, "gobuster_dirs.txt")

    try:
        cmd = [
            "gobuster", "dir",
            "-u", target,
            "-w", wordlist,
            "-o", output,
            "-b", "403,404",  # Exclude common error codes
            "-t", "10",       # 10 threads
            "-q",             # Quiet mode
            "--timeout", "10s"
        ]

        logger.info(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        if result.returncode == 0:
            logger.info(f"Gobuster completed successfully. Results saved to {output}")

            # Count discovered directories
            if os.path.exists(output):
                with open(output, 'r') as f:
                    dirs_found = len([line for line in f if line.strip() and not line.startswith('=')])
                logger.info(f"Discovered {dirs_found} directories/files")

            return True
        else:
            logger.error(f"Gobuster failed with return code {result.returncode}")
            logger.error(f"stderr: {result.stderr}")
            return False

    except subprocess.TimeoutExpired:
        logger.error(f"Gobuster timed out after {timeout} seconds")
        return False
    except FileNotFoundError:
        logger.error("gobuster not installed. Please install gobuster.")
        return False
    except Exception as e:
        logger.error(f"Gobuster execution failed: {e}")
        return False

def parse_args():
    """Enhanced argument parsing with configuration integration"""
    config = get_config()

    p = argparse.ArgumentParser(
        description="Caido-Hunt - Advanced Web Application Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u https://example.com --gui
  %(prog)s --target https://test.com --depth 5 --workers 8
  %(prog)s -u https://app.com --zap --sqlmap --gobuster
  %(prog)s --target https://site.com --ai-api-key sk-xxx --filter-high-impact

Configuration:
  Settings can be customized via config.json or environment variables.
  Run with --health-check to verify system readiness.
        """
    )

    # Core arguments
    p.add_argument("-u", "--target",
                   help="Target root URL (https://example.com)")
    p.add_argument("--proxy", default=config.get('proxy.default_url'),
                   help=f"Proxy (Caido) URL (default: {config.get('proxy.default_url')})")
    p.add_argument("--no-proxy", action="store_true",
                   help="Run without proxy (direct requests)")

    # Crawling configuration
    crawl_group = p.add_argument_group('Crawling Options')
    crawl_group.add_argument("--depth", type=int, default=config.get('crawler.default_depth'),
                            help=f"Crawl depth (default: {config.get('crawler.default_depth')})")
    crawl_group.add_argument("--max-pages", type=int, default=config.get('crawler.max_pages'),
                            help=f"Max pages to crawl (default: {config.get('crawler.max_pages')})")
    crawl_group.add_argument("--workers", type=int, default=config.get('crawler.workers'),
                            help=f"Concurrent workers (default: {config.get('crawler.workers')})")
    crawl_group.add_argument("--sleep", type=float, default=config.get('crawler.sleep_between_requests'),
                            help=f"Seconds between requests (default: {config.get('crawler.sleep_between_requests')})")

    # Authentication
    auth_group = p.add_argument_group('Authentication')
    auth_group.add_argument("--cookie-file",
                           help="Cookie file (k=v per line or JSON) for authenticated tests")
    auth_group.add_argument("--login-url", help="URL to POST login credentials")
    auth_group.add_argument("--login-data",
                           help="Login JSON string, e.g. '{\"username\":\"u\",\"password\":\"p\"}'")

    # Scanning options
    scan_group = p.add_argument_group('Scanning Options')
    scan_group.add_argument("--denylist-file",
                           help="File with regex patterns for URL denylist")
    scan_group.add_argument("--screenshot", action="store_true", default=config.get('scanner.enable_screenshots'),
                           help="Take screenshots for PoC (requires selenium/geckodriver)")
    scan_group.add_argument("--headless", action="store_true", default=config.get('scanner.headless_browser'),
                           help="Use headless browser for crawling")
    scan_group.add_argument("--no-active", action="store_true",
                           help="Discovery only mode (no active vulnerability testing)")
    scan_group.add_argument("--filter-high-impact", action="store_true",
                           default=config.get('reporting.filter_high_impact_only'),
                           help="Filter to only high-impact vulnerabilities")

    # Integration options
    integration_group = p.add_argument_group('Integrations')
    integration_group.add_argument("--zap", action="store_true",
                                  help="Integrate with OWASP ZAP for automated scanning")
    integration_group.add_argument("--sqlmap", action="store_true",
                                  help="Run sqlmap on detected SQLi findings")
    integration_group.add_argument("--gobuster", action="store_true",
                                  help="Run gobuster for directory enumeration")
    integration_group.add_argument("--nuclei", action="store_true",
                                  help="Run nuclei for additional vulnerability scanning")

    # Reporting and analysis
    report_group = p.add_argument_group('Reporting & Analysis')
    report_group.add_argument("--elk-url", default=config.get('reporting.elk_url'),
                             help="ELK ingestion endpoint for real-time data")
    report_group.add_argument("--bounty-url", default=config.get('reporting.bounty_webhook'),
                             help="Bounty program webhook for finding submissions")
    report_group.add_argument("--ai-api-key", default=config.get('reporting.openai_api_key'),
                             help="OpenAI API key for AI-powered analysis")

    # Interface options
    interface_group = p.add_argument_group('Interface Options')
    interface_group.add_argument("--gui", action="store_true", dest="gui",
                                help="Start web GUI for real-time monitoring")
    interface_group.add_argument("--no-gui", action="store_false", dest="gui",
                                help="Disable web GUI")
    interface_group.set_defaults(gui=config.get('gui.enabled'))
    interface_group.add_argument("--gui-port", type=int, default=config.get('gui.port'),
                                help=f"GUI port (default: {config.get('gui.port')})")

    # System options
    system_group = p.add_argument_group('System Options')
    system_group.add_argument("--config", help="Configuration file path")
    system_group.add_argument("--health-check", action="store_true",
                             help="Run comprehensive health check and exit")
    system_group.add_argument("--verbose", "-v", action="store_true",
                             help="Enable verbose logging")
    system_group.add_argument("--log-file", help="Log file path")
    system_group.add_argument("--version", action="version", version="Caido-Hunt 2.1")

    return p.parse_args()

def signal_handler(signum, frame):
    """Handle interrupt signals gracefully"""
    logger.info("Received interrupt signal. Shutting down gracefully...")
    sys.exit(0)

def run_nuclei_scan(target, results_dir, config):
    """Enhanced Nuclei integration"""
    if not config.get('integrations.nuclei.enabled'):
        logger.warning("Nuclei integration is disabled in configuration")
        return False

    logger.info("Running nuclei vulnerability scan...")

    templates_dir = config.get('integrations.nuclei.templates_dir', '~/nuclei-templates')
    templates_dir = os.path.expanduser(templates_dir)
    timeout = config.get('integrations.nuclei.timeout', 600)

    output_file = os.path.join(results_dir, "nuclei_results.json")

    try:
        cmd = [
            "nuclei",
            "-u", target,
            "-t", templates_dir,
            "-json",
            "-o", output_file,
            "-rate-limit", "10",
            "-timeout", "10"
        ]

        logger.info(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        if result.returncode == 0:
            logger.info(f"Nuclei scan completed successfully. Results saved to {output_file}")

            # Count findings
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    findings = len([line for line in f if line.strip()])
                logger.info(f"Nuclei found {findings} potential vulnerabilities")

            return True
        else:
            logger.error(f"Nuclei failed with return code {result.returncode}")
            logger.error(f"stderr: {result.stderr}")
            return False

    except subprocess.TimeoutExpired:
        logger.error(f"Nuclei timed out after {timeout} seconds")
        return False
    except FileNotFoundError:
        logger.error("nuclei not installed. Please install nuclei.")
        return False
    except Exception as e:
        logger.error(f"Nuclei execution failed: {e}")
        return False

def main():
    """Enhanced main function with improved error handling and features"""
    # Install signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        args = parse_args()

        # Reload configuration if custom config specified
        if args.config:
            reload_config(args.config)
            logger.info(f"Loaded configuration from {args.config}")

        config = get_config()

        # Setup logging
        log_level = logging.DEBUG if args.verbose else logging.INFO
        setup_logging(log_level, args.log_file)

        # Health check mode
        if args.health_check:
            logger.info("Running comprehensive health check...")
            checker = HealthChecker(args.config)
            report = checker.run_all_checks(
                include_network=True,
                proxy_url=args.proxy if not args.no_proxy else None
            )

            # Print summary
            summary = report['summary']
            print(f"\n{'='*70}")
            print(f"CAIDO-HUNT HEALTH CHECK")
            print(f"{'='*70}")
            print(f"Overall Status: {summary['overall_status']}")
            print(f"Checks Passed: {summary['checks_passed']}/{summary['checks_total']}")
            print(f"Success Rate: {summary['success_rate']:.1f}%")
            print(f"{'='*70}\n")

            # Print failed checks
            for check_name, result in report['checks'].items():
                status = "✓" if result['status'] == 'PASS' else "✗"
                print(f"{status} {check_name}: {result['message']}")

            sys.exit(0 if summary['overall_status'] == 'HEALTHY' else 1)

        # Check if target is provided for non-health-check operations
        if not args.target:
            logger.error("Target URL is required for scanning operations")
            logger.info("Use --health-check to run system diagnostics without a target")
            sys.exit(1)

        # Validate target URL
        is_valid, normalized_url, error_msg = validate_url(args.target)
        if not is_valid:
            logger.error(f"Invalid target URL: {error_msg}")
            sys.exit(1)

        args.target = normalized_url
        proxy = None if args.no_proxy else args.proxy

        logger.info("="*70)
        logger.info("CAIDO-HUNT SECURITY SCANNER v2.1")
        logger.info("="*70)
        logger.info(f"Target: {args.target}")
        logger.info(f"Proxy: {proxy if proxy else 'Direct connection'}")
        logger.info(f"Depth: {args.depth}, Max Pages: {args.max_pages}, Workers: {args.workers}")
        logger.info(f"Features: GUI={args.gui}, Screenshots={args.screenshot}, Headless={args.headless}")
        logger.info(f"Integrations: ZAP={args.zap}, SQLmap={args.sqlmap}, Gobuster={args.gobuster}")
        logger.info("="*70)

        # Initialize scanner core
        try:
            core = ScannerCore(
                root=args.target,
                proxy=proxy,
                depth=args.depth,
                max_pages=args.max_pages,
                workers=args.workers,
                sleep=args.sleep,
                cookie_file=args.cookie_file,
                login_url=args.login_url,
                login_data=args.login_data,
                denylist_file=args.denylist_file,
                screenshot=args.screenshot,
                elk_url=args.elk_url,
                bounty_url=args.bounty_url,
                ai_api_key=args.ai_api_key,
                gui=args.gui,
                headless=args.headless,
                filter_high_impact=args.filter_high_impact
            )

            # Run the scan
            logger.info("Starting vulnerability scan...")
            core.run(disable_active=args.no_active)
            logger.info("Main scan completed successfully")

            # Post-scan integrations
            integration_results = {
                'zap': False,
                'sqlmap': False,
                'gobuster': False,
                'nuclei': False
            }

            if args.zap:
                logger.info("Running OWASP ZAP integration...")
                integration_results['zap'] = run_zap_scan(args.target, core.results_dir, config)

            if args.sqlmap:
                logger.info("Running SQLmap integration...")
                integration_results['sqlmap'] = run_sqlmap_on_findings(core.results_dir, config)

            if args.gobuster:
                logger.info("Running Gobuster integration...")
                integration_results['gobuster'] = run_gobuster(args.target, core.results_dir, config)

            if args.nuclei:
                logger.info("Running Nuclei integration...")
                integration_results['nuclei'] = run_nuclei_scan(args.target, core.results_dir, config)

            # Generate final summary
            logger.info("="*70)
            logger.info("SCAN SUMMARY")
            logger.info("="*70)
            logger.info(f"Target: {args.target}")
            logger.info(f"Pages Crawled: {core.pages}")
            logger.info(f"Results Directory: {core.results_dir}")

            if any(integration_results.values()):
                logger.info("Integration Results:")
                for integration, success in integration_results.items():
                    if integration_results[integration] is not False:
                        status = "✓" if success else "✗"
                        logger.info(f"  {status} {integration.upper()}: {'Success' if success else 'Failed'}")

            logger.info("="*70)
            logger.info("Scan completed successfully! Check the results directory for detailed findings.")

        except KeyboardInterrupt:
            logger.info("Scan interrupted by user")
            sys.exit(0)
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)

    except Exception as e:
        logger.error(f"Fatal error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
