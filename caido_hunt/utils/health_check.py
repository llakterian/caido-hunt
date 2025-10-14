#!/usr/bin/env python3
"""
health_check.py - Comprehensive health check and monitoring system for caido-hunt
"""
import os
import sys
import time
import json
import logging
import psutil
import threading
import subprocess
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
import requests
from requests.exceptions import RequestException

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class HealthMetrics:
    """System and application health metrics"""

    def __init__(self):
        self.start_time = datetime.now()
        self.checks_performed = 0
        self.checks_passed = 0
        self.checks_failed = 0
        self.last_check_time = None
        self.alerts = []

    def add_check_result(self, passed: bool, check_name: str, details: str = ""):
        """Record a health check result"""
        self.checks_performed += 1
        if passed:
            self.checks_passed += 1
        else:
            self.checks_failed += 1
            self.alerts.append({
                'timestamp': datetime.now().isoformat(),
                'check': check_name,
                'details': details,
                'severity': 'error'
            })
        self.last_check_time = datetime.now()

    def get_success_rate(self) -> float:
        """Get check success rate percentage"""
        if self.checks_performed == 0:
            return 100.0
        return (self.checks_passed / self.checks_performed) * 100

    def get_uptime(self) -> timedelta:
        """Get system uptime"""
        return datetime.now() - self.start_time

class HealthChecker:
    """Comprehensive health checker for caido-hunt"""

    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or "config.json"
        self.metrics = HealthMetrics()
        self.script_dir = Path(__file__).parent.absolute()
        self.required_files = [
            "hunt.py",
            "scanner_core.py",
            "utils.py",
            "reporter.py",
            "config.py",
            "requirements.txt"
        ]
        self.required_dirs = [
            "modules",
            "caido-env"
        ]

    def check_python_environment(self) -> Tuple[bool, str]:
        """Check Python version and virtual environment"""
        try:
            # Check Python version
            version = sys.version_info
            if version.major < 3 or (version.major == 3 and version.minor < 8):
                return False, f"Python {version.major}.{version.minor} is too old, requires 3.8+"

            # Check if we're in virtual environment
            if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
                venv_status = "Active virtual environment detected"
            else:
                venv_path = self.script_dir / "caido-env"
                if venv_path.exists():
                    venv_status = "Virtual environment available but not activated"
                else:
                    return False, "No virtual environment found"

            return True, f"Python {version.major}.{version.minor}.{version.micro}, {venv_status}"

        except Exception as e:
            return False, f"Python environment check failed: {e}"

    def check_dependencies(self) -> Tuple[bool, str]:
        """Check if all required Python dependencies are installed"""
        try:
            requirements_file = self.script_dir / "requirements.txt"
            if not requirements_file.exists():
                return False, "requirements.txt not found"

            with open(requirements_file, 'r') as f:
                requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

            missing_deps = []
            # Map of package names to import names
            package_import_map = {
                'beautifulsoup4': 'bs4',
                'python-owasp-zap-v2.4': 'zapv2',
                'flask-socketio': 'flask_socketio'
            }

            for req in requirements:
                # Simple package name extraction (ignoring version specs)
                package_name = req.split('==')[0].split('>=')[0].split('<=')[0].split('>')[0].split('<')[0].strip()

                # Get the correct import name
                import_name = package_import_map.get(package_name, package_name.replace('-', '_'))

                try:
                    __import__(import_name)
                except ImportError:
                    missing_deps.append(package_name)

            if missing_deps:
                return False, f"Missing dependencies: {', '.join(missing_deps)}"

            return True, f"All {len(requirements)} dependencies are installed"

        except Exception as e:
            return False, f"Dependency check failed: {e}"

    def check_file_structure(self) -> Tuple[bool, str]:
        """Check if required files and directories exist"""
        try:
            missing_files = []
            missing_dirs = []

            # Check required files
            for file_name in self.required_files:
                file_path = self.script_dir / file_name
                if not file_path.exists():
                    missing_files.append(file_name)

            # Check required directories
            for dir_name in self.required_dirs:
                dir_path = self.script_dir / dir_name
                if not dir_path.exists():
                    missing_dirs.append(dir_name)

            if missing_files or missing_dirs:
                missing = []
                if missing_files:
                    missing.extend([f"files: {', '.join(missing_files)}"])
                if missing_dirs:
                    missing.extend([f"directories: {', '.join(missing_dirs)}"])
                return False, f"Missing {'; '.join(missing)}"

            return True, f"All required files and directories present"

        except Exception as e:
            return False, f"File structure check failed: {e}"

    def check_geckodriver(self) -> Tuple[bool, str]:
        """Check Geckodriver availability and version"""
        try:
            geckodriver_paths = [
                self.script_dir / "geckodriver",
                "/usr/local/bin/geckodriver",
                "/usr/bin/geckodriver"
            ]

            for geckodriver_path in geckodriver_paths:
                if geckodriver_path.exists():
                    try:
                        result = subprocess.run([str(geckodriver_path), "--version"],
                                              capture_output=True, text=True, timeout=10)
                        if result.returncode == 0:
                            version_line = result.stdout.split('\n')[0]
                            return True, f"Geckodriver found: {version_line}"
                    except subprocess.TimeoutExpired:
                        return False, f"Geckodriver at {geckodriver_path} timed out"
                    except Exception as e:
                        continue

            return False, "Geckodriver not found in expected locations"

        except Exception as e:
            return False, f"Geckodriver check failed: {e}"

    def check_firefox(self) -> Tuple[bool, str]:
        """Check Firefox browser availability"""
        try:
            firefox_commands = ["firefox", "firefox-esr", "/usr/bin/firefox"]

            for cmd in firefox_commands:
                try:
                    result = subprocess.run([cmd, "--version"],
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        version_info = result.stdout.strip()
                        return True, f"Firefox found: {version_info}"
                except FileNotFoundError:
                    continue
                except subprocess.TimeoutExpired:
                    return False, f"Firefox command '{cmd}' timed out"
                except Exception:
                    continue

            return False, "Firefox not found"

        except Exception as e:
            return False, f"Firefox check failed: {e}"

    def check_disk_space(self, min_free_gb: float = 1.0) -> Tuple[bool, str]:
        """Check available disk space"""
        try:
            disk_usage = psutil.disk_usage(self.script_dir)
            free_gb = disk_usage.free / (1024**3)
            total_gb = disk_usage.total / (1024**3)
            used_percent = (disk_usage.used / disk_usage.total) * 100

            if free_gb < min_free_gb:
                return False, f"Low disk space: {free_gb:.2f}GB free ({used_percent:.1f}% used)"

            return True, f"Disk space OK: {free_gb:.2f}GB free of {total_gb:.2f}GB ({used_percent:.1f}% used)"

        except Exception as e:
            return False, f"Disk space check failed: {e}"

    def check_memory(self, min_free_mb: float = 512.0) -> Tuple[bool, str]:
        """Check available memory"""
        try:
            memory = psutil.virtual_memory()
            free_mb = memory.available / (1024**2)
            total_gb = memory.total / (1024**3)
            used_percent = memory.percent

            if free_mb < min_free_mb:
                return False, f"Low memory: {free_mb:.0f}MB available ({used_percent:.1f}% used)"

            return True, f"Memory OK: {free_mb:.0f}MB available of {total_gb:.1f}GB ({used_percent:.1f}% used)"

        except Exception as e:
            return False, f"Memory check failed: {e}"

    def check_network_connectivity(self, test_url: str = "https://httpbin.org/ip") -> Tuple[bool, str]:
        """Check network connectivity"""
        try:
            response = requests.get(test_url, timeout=10)
            if response.status_code == 200:
                return True, f"Network connectivity OK (response time: {response.elapsed.total_seconds():.2f}s)"
            else:
                return False, f"Network test failed with status code: {response.status_code}"

        except RequestException as e:
            return False, f"Network connectivity failed: {e}"
        except Exception as e:
            return False, f"Network check failed: {e}"

    def check_proxy_connectivity(self, proxy_url: str = "http://127.0.0.1:8080") -> Tuple[bool, str]:
        """Check proxy connectivity (Caido)"""
        try:
            proxies = {
                'http': proxy_url,
                'https': proxy_url
            }

            # Try to connect through proxy with a simple request
            response = requests.get("https://httpbin.org/ip", proxies=proxies, timeout=10)
            if response.status_code == 200:
                return True, f"Proxy connectivity OK via {proxy_url}"
            else:
                return False, f"Proxy test failed with status code: {response.status_code}"

        except RequestException as e:
            return False, f"Proxy connectivity failed: {e}"
        except Exception as e:
            return False, f"Proxy check failed: {e}"

    def check_configuration(self) -> Tuple[bool, str]:
        """Check configuration file validity"""
        try:
            config_path = self.script_dir / self.config_file
            if not config_path.exists():
                return True, "No custom config file (using defaults)"

            with open(config_path, 'r') as f:
                config_data = json.load(f)

            # Basic validation
            if not isinstance(config_data, dict):
                return False, "Configuration file is not a valid JSON object"

            # Check for required sections (if they exist)
            sections = ['proxy', 'crawler', 'scanner', 'paths']
            present_sections = [s for s in sections if s in config_data]

            return True, f"Configuration valid with {len(present_sections)} sections: {', '.join(present_sections)}"

        except json.JSONDecodeError as e:
            return False, f"Configuration JSON parse error: {e}"
        except Exception as e:
            return False, f"Configuration check failed: {e}"

    def check_modules(self) -> Tuple[bool, str]:
        """Check vulnerability detection modules"""
        try:
            modules_dir = self.script_dir / "modules"
            if not modules_dir.exists():
                return False, "Modules directory not found"

            module_files = list(modules_dir.glob("*.py"))
            # Exclude __init__.py and __pycache__
            module_files = [f for f in module_files if f.name != "__init__.py"]

            if not module_files:
                return False, "No vulnerability modules found"

            # Try to validate modules by importing them
            valid_modules = []
            invalid_modules = []

            for module_file in module_files:
                module_name = module_file.stem
                try:
                    import importlib.util
                    spec = importlib.util.spec_from_file_location(module_name, module_file)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)

                    if hasattr(module, 'register'):
                        config = module.register()
                        if isinstance(config, dict) and 'name' in config:
                            valid_modules.append(module_name)
                        else:
                            invalid_modules.append(f"{module_name} (invalid config)")
                    else:
                        invalid_modules.append(f"{module_name} (no register function)")

                except Exception as e:
                    invalid_modules.append(f"{module_name} ({str(e)[:50]})")

            if invalid_modules:
                return False, f"Found {len(valid_modules)} valid modules, {len(invalid_modules)} invalid: {', '.join(invalid_modules[:3])}"

            return True, f"All {len(valid_modules)} modules are valid: {', '.join(valid_modules)}"

        except Exception as e:
            return False, f"Modules check failed: {e}"

    def check_results_directory(self) -> Tuple[bool, str]:
        """Check results directory writability"""
        try:
            results_dir = self.script_dir / "caido_results"

            # Create directory if it doesn't exist
            results_dir.mkdir(exist_ok=True)

            # Test write permissions
            test_file = results_dir / ".health_check_test"
            try:
                with open(test_file, 'w') as f:
                    f.write("test")
                test_file.unlink()  # Remove test file

                return True, f"Results directory writable: {results_dir}"

            except PermissionError:
                return False, f"Results directory not writable: {results_dir}"

        except Exception as e:
            return False, f"Results directory check failed: {e}"

    def run_all_checks(self, include_network: bool = True, proxy_url: Optional[str] = None) -> Dict[str, Any]:
        """Run all health checks and return comprehensive report"""
        checks = [
            ("Python Environment", self.check_python_environment),
            ("Dependencies", self.check_dependencies),
            ("File Structure", self.check_file_structure),
            ("Configuration", self.check_configuration),
            ("Modules", self.check_modules),
            ("Geckodriver", self.check_geckodriver),
            ("Firefox", self.check_firefox),
            ("Disk Space", self.check_disk_space),
            ("Memory", self.check_memory),
            ("Results Directory", self.check_results_directory),
        ]

        if include_network:
            checks.append(("Network Connectivity", self.check_network_connectivity))

        if proxy_url:
            checks.append(("Proxy Connectivity", lambda: self.check_proxy_connectivity(proxy_url)))

        results = {}
        overall_status = True

        logger.info("Running comprehensive health checks...")

        for check_name, check_func in checks:
            try:
                logger.info(f"Checking {check_name}...")
                passed, message = check_func()
                results[check_name] = {
                    'status': 'PASS' if passed else 'FAIL',
                    'message': message,
                    'timestamp': datetime.now().isoformat()
                }

                self.metrics.add_check_result(passed, check_name, message)

                if passed:
                    logger.info(f"✓ {check_name}: {message}")
                else:
                    logger.error(f"✗ {check_name}: {message}")
                    overall_status = False

            except Exception as e:
                error_msg = f"Check execution failed: {e}"
                results[check_name] = {
                    'status': 'ERROR',
                    'message': error_msg,
                    'timestamp': datetime.now().isoformat()
                }
                self.metrics.add_check_result(False, check_name, error_msg)
                logger.error(f"✗ {check_name}: {error_msg}")
                overall_status = False

        # Generate summary
        summary = {
            'overall_status': 'HEALTHY' if overall_status else 'UNHEALTHY',
            'checks_total': len(checks),
            'checks_passed': sum(1 for r in results.values() if r['status'] == 'PASS'),
            'checks_failed': sum(1 for r in results.values() if r['status'] in ['FAIL', 'ERROR']),
            'success_rate': self.metrics.get_success_rate(),
            'timestamp': datetime.now().isoformat(),
            'uptime': str(self.metrics.get_uptime())
        }

        return {
            'summary': summary,
            'checks': results,
            'metrics': {
                'total_checks_performed': self.metrics.checks_performed,
                'alerts': self.metrics.alerts[-10:]  # Last 10 alerts
            },
            'system_info': self._get_system_info()
        }

    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information"""
        try:
            return {
                'platform': {
                    'system': os.name,
                    'platform': sys.platform,
                    'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                    'architecture': os.uname().machine if hasattr(os, 'uname') else 'unknown'
                },
                'resources': {
                    'cpu_count': psutil.cpu_count(),
                    'memory_total_gb': round(psutil.virtual_memory().total / (1024**3), 2),
                    'disk_total_gb': round(psutil.disk_usage(self.script_dir).total / (1024**3), 2)
                },
                'paths': {
                    'script_dir': str(self.script_dir),
                    'python_executable': sys.executable,
                    'working_directory': os.getcwd()
                }
            }
        except Exception as e:
            return {'error': f"Failed to collect system info: {e}"}

class HealthMonitor:
    """Continuous health monitoring service"""

    def __init__(self, check_interval: int = 300, config_file: Optional[str] = None):
        self.check_interval = check_interval  # seconds
        self.config_file = config_file
        self.checker = HealthChecker(config_file)
        self.monitoring = False
        self.monitor_thread = None
        self.latest_report = None

    def start_monitoring(self):
        """Start continuous monitoring"""
        if self.monitoring:
            logger.warning("Monitoring is already running")
            return

        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info(f"Health monitoring started (interval: {self.check_interval}s)")

    def stop_monitoring(self):
        """Stop continuous monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Health monitoring stopped")

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                self.latest_report = self.checker.run_all_checks(include_network=False)

                # Log summary
                summary = self.latest_report['summary']
                logger.info(f"Health check completed: {summary['overall_status']} "
                           f"({summary['checks_passed']}/{summary['checks_total']} passed)")

                # Alert on failures
                if summary['overall_status'] != 'HEALTHY':
                    failed_checks = [name for name, result in self.latest_report['checks'].items()
                                   if result['status'] in ['FAIL', 'ERROR']]
                    logger.warning(f"Health check failures: {', '.join(failed_checks)}")

            except Exception as e:
                logger.error(f"Health monitoring error: {e}")

            # Wait for next check
            for _ in range(self.check_interval):
                if not self.monitoring:
                    break
                time.sleep(1)

    def get_latest_report(self) -> Optional[Dict[str, Any]]:
        """Get the latest health report"""
        return self.latest_report

def main():
    """Main function for standalone execution"""
    import argparse

    parser = argparse.ArgumentParser(description="Caido-Hunt Health Check System")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--proxy", help="Proxy URL to test (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--no-network", action="store_true", help="Skip network connectivity tests")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--monitor", type=int, help="Start continuous monitoring (check interval in seconds)")
    parser.add_argument("--output", help="Save results to file")

    args = parser.parse_args()

    checker = HealthChecker(args.config)

    if args.monitor:
        # Start monitoring mode
        monitor = HealthMonitor(args.monitor, args.config)
        monitor.start_monitoring()

        try:
            print(f"Health monitoring started (interval: {args.monitor}s). Press Ctrl+C to stop.")
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping health monitoring...")
            monitor.stop_monitoring()
    else:
        # Single check mode
        report = checker.run_all_checks(
            include_network=not args.no_network,
            proxy_url=args.proxy
        )

        if args.json:
            output = json.dumps(report, indent=2)
        else:
            # Human-readable output
            summary = report['summary']
            output = f"""
╔══════════════════════════════════════════════════════════════════════════════════╗
║                           CAIDO-HUNT HEALTH CHECK REPORT                        ║
╚══════════════════════════════════════════════════════════════════════════════════╝

Overall Status: {summary['overall_status']}
Checks Passed: {summary['checks_passed']}/{summary['checks_total']} ({summary['success_rate']:.1f}%)
Timestamp: {summary['timestamp']}

DETAILED RESULTS:
"""

            for check_name, result in report['checks'].items():
                status_icon = "✓" if result['status'] == 'PASS' else "✗"
                output += f"{status_icon} {check_name}: {result['message']}\n"

            if report['metrics']['alerts']:
                output += "\nRECENT ALERTS:\n"
                for alert in report['metrics']['alerts']:
                    output += f"- {alert['timestamp']}: {alert['check']} - {alert['details']}\n"

        print(output)

        if args.output:
            with open(args.output, 'w') as f:
                if args.json:
                    json.dump(report, f, indent=2)
                else:
                    f.write(output)
            print(f"\nResults saved to: {args.output}")

        # Exit with appropriate code
        sys.exit(0 if summary['overall_status'] == 'HEALTHY' else 1)

if __name__ == "__main__":
    main()
