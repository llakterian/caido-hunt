#!/usr/bin/env python3
"""
config.py - Configuration management for caido-hunt scanner
"""
import os
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class Config:
    """Configuration manager for caido-hunt with environment variable support and validation"""

    def __init__(self, config_file=None):
        self.config_file = config_file or os.path.join(os.path.dirname(__file__), "config.json")
        self.config = self._load_default_config()

        # Load from file if exists
        if os.path.exists(self.config_file):
            self._load_config_file()

        # Override with environment variables
        self._load_env_vars()

        # Validate configuration
        self._validate_config()

    def _load_default_config(self):
        """Default configuration values"""
        return {
            "proxy": {
                "default_url": "http://127.0.0.1:8080",
                "timeout": 30,
                "verify_ssl": False,
                "user_agent": "caido-hunt/2.1"
            },
            "crawler": {
                "default_depth": 3,
                "max_pages": 500,
                "workers": 4,
                "sleep_between_requests": 0.5,
                "request_timeout": 15,
                "max_retries": 3,
                "retry_backoff": 2.0
            },
            "scanner": {
                "enable_screenshots": True,
                "screenshot_timeout": 30,
                "headless_browser": True,
                "max_payload_length": 1000,
                "vulnerability_timeout": 20
            },
            "paths": {
                "geckodriver": "./geckodriver",
                "wordlists": "./wordlists",
                "results_dir": "./caido_results",
                "modules_dir": "./modules"
            },
            "integrations": {
                "zap": {
                    "enabled": False,
                    "api_key": "your-api-key",
                    "host": "127.0.0.1",
                    "port": 8090
                },
                "sqlmap": {
                    "enabled": False,
                    "timeout": 300,
                    "batch_mode": True
                },
                "gobuster": {
                    "enabled": False,
                    "wordlist": "/usr/share/wordlists/dirb/common.txt",
                    "timeout": 300
                },
                "nuclei": {
                    "enabled": False,
                    "templates_dir": "~/nuclei-templates",
                    "timeout": 600
                }
            },
            "reporting": {
                "formats": ["json", "csv", "markdown", "html"],
                "elk_integration": False,
                "elk_url": None,
                "bounty_webhook": None,
                "ai_analysis": False,
                "openai_api_key": None,
                "filter_high_impact_only": False
            },
            "gui": {
                "enabled": True,
                "host": "127.0.0.1",
                "port": 5000,
                "debug": False
            },
            "logging": {
                "level": "INFO",
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "file": None,
                "max_file_size": "10MB",
                "backup_count": 5
            },
            "security": {
                "denylist_patterns": [
                    r"/logout",
                    r"/sso",
                    r"/signin",
                    r"/checkout",
                    r"/payment",
                    r"/admin",
                    r"/api/auth",
                    r"/oauth",
                    r"/static",
                    r"/assets",
                    r"/wp-admin",
                    r"/wp-content"
                ],
                "high_impact_vulnerabilities": [
                    "Potential RCE (Command Injection)",
                    "SQL Injection",
                    "Local File Inclusion",
                    "Server-Side Request Forgery"
                ],
                "auth_keywords": [
                    "login", "auth", "password", "session",
                    "account", "user", "admin", "signin", "signup"
                ]
            }
        }

    def _load_config_file(self):
        """Load configuration from JSON file"""
        try:
            with open(self.config_file, 'r') as f:
                file_config = json.load(f)
                self._merge_config(self.config, file_config)
            logger.info(f"Configuration loaded from {self.config_file}")
        except Exception as e:
            logger.warning(f"Failed to load config file {self.config_file}: {e}")

    def _load_env_vars(self):
        """Load configuration from environment variables"""
        env_mappings = {
            'CAIDO_PROXY_URL': ('proxy', 'default_url'),
            'CAIDO_MAX_PAGES': ('crawler', 'max_pages'),
            'CAIDO_WORKERS': ('crawler', 'workers'),
            'CAIDO_DEPTH': ('crawler', 'default_depth'),
            'CAIDO_SLEEP': ('crawler', 'sleep_between_requests'),
            'CAIDO_SCREENSHOTS': ('scanner', 'enable_screenshots'),
            'CAIDO_HEADLESS': ('scanner', 'headless_browser'),
            'CAIDO_GECKODRIVER_PATH': ('paths', 'geckodriver'),
            'CAIDO_RESULTS_DIR': ('paths', 'results_dir'),
            'CAIDO_ZAP_ENABLED': ('integrations', 'zap', 'enabled'),
            'CAIDO_ZAP_API_KEY': ('integrations', 'zap', 'api_key'),
            'CAIDO_SQLMAP_ENABLED': ('integrations', 'sqlmap', 'enabled'),
            'CAIDO_ELK_URL': ('reporting', 'elk_url'),
            'CAIDO_BOUNTY_WEBHOOK': ('reporting', 'bounty_webhook'),
            'CAIDO_OPENAI_API_KEY': ('reporting', 'openai_api_key'),
            'CAIDO_AI_ANALYSIS': ('reporting', 'ai_analysis'),
            'CAIDO_GUI_ENABLED': ('gui', 'enabled'),
            'CAIDO_GUI_PORT': ('gui', 'port'),
            'CAIDO_LOG_LEVEL': ('logging', 'level'),
            'CAIDO_LOG_FILE': ('logging', 'file'),
            'CAIDO_FILTER_HIGH_IMPACT': ('reporting', 'filter_high_impact_only')
        }

        for env_var, config_path in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                self._set_nested_config(config_path, self._convert_env_value(value))

    def _convert_env_value(self, value):
        """Convert environment variable string to appropriate type"""
        if value.lower() in ('true', '1', 'yes', 'on'):
            return True
        elif value.lower() in ('false', '0', 'no', 'off'):
            return False
        elif value.isdigit():
            return int(value)
        elif self._is_float(value):
            return float(value)
        return value

    def _is_float(self, value):
        """Check if string represents a float"""
        try:
            float(value)
            return True
        except ValueError:
            return False

    def _set_nested_config(self, config_path, value):
        """Set nested configuration value"""
        config_ref = self.config
        for key in config_path[:-1]:
            if key not in config_ref:
                config_ref[key] = {}
            config_ref = config_ref[key]
        config_ref[config_path[-1]] = value

    def _merge_config(self, base, override):
        """Recursively merge configuration dictionaries"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value

    def _validate_config(self):
        """Validate configuration values"""
        # Validate required paths
        geckodriver_path = self.get('paths.geckodriver')
        if not os.path.exists(geckodriver_path):
            logger.warning(f"Geckodriver not found at {geckodriver_path}")

        # Validate numeric ranges
        max_pages = self.get('crawler.max_pages')
        if max_pages < 1:
            logger.warning("max_pages should be at least 1")

        workers = self.get('crawler.workers')
        if workers < 1 or workers > 50:
            logger.warning("workers should be between 1 and 50")

        depth = self.get('crawler.default_depth')
        if depth < 1 or depth > 10:
            logger.warning("depth should be between 1 and 10")

        sleep = self.get('crawler.sleep_between_requests')
        if sleep < 0:
            logger.warning("sleep_between_requests should be non-negative")

        # Validate integrations
        if self.get('integrations.zap.enabled'):
            if not self.get('integrations.zap.api_key') or self.get('integrations.zap.api_key') == 'your-api-key':
                logger.warning("ZAP integration enabled but API key not configured")

        if self.get('reporting.ai_analysis'):
            if not self.get('reporting.openai_api_key'):
                logger.warning("AI analysis enabled but OpenAI API key not configured")

        logger.info("Configuration validation completed")

    def get(self, key, default=None):
        """Get configuration value using dot notation (e.g., 'proxy.default_url')"""
        keys = key.split('.')
        value = self.config

        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default

    def set(self, key, value):
        """Set configuration value using dot notation"""
        keys = key.split('.')
        config_ref = self.config

        for k in keys[:-1]:
            if k not in config_ref:
                config_ref[k] = {}
            config_ref = config_ref[k]

        config_ref[keys[-1]] = value

    def save(self, file_path=None):
        """Save current configuration to file"""
        file_path = file_path or self.config_file
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w') as f:
                json.dump(self.config, f, indent=2)
            logger.info(f"Configuration saved to {file_path}")
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")

    def export_template(self, file_path=None):
        """Export default configuration template"""
        file_path = file_path or "config.template.json"
        try:
            with open(file_path, 'w') as f:
                json.dump(self._load_default_config(), f, indent=2)
            logger.info(f"Configuration template exported to {file_path}")
        except Exception as e:
            logger.error(f"Failed to export configuration template: {e}")

    def validate_target_url(self, url):
        """Validate target URL format"""
        if not url:
            return False, "URL is required"

        if not url.startswith(('http://', 'https://')):
            return False, "URL must start with http:// or https://"

        return True, "URL is valid"

    def get_denylist_patterns(self):
        """Get compiled denylist regex patterns"""
        import re
        patterns = self.get('security.denylist_patterns', [])
        return [re.compile(pattern, re.I) for pattern in patterns]

    def is_high_impact_vulnerability(self, vul_type):
        """Check if vulnerability type is considered high impact"""
        high_impact = self.get('security.high_impact_vulnerabilities', [])
        return vul_type in high_impact

    def is_auth_related_endpoint(self, endpoint):
        """Check if endpoint appears to be authentication related"""
        endpoint_lower = endpoint.lower()
        auth_keywords = self.get('security.auth_keywords', [])
        return any(keyword in endpoint_lower for keyword in auth_keywords)

# Global configuration instance
config = Config()

def get_config():
    """Get the global configuration instance"""
    return config

def reload_config(config_file=None):
    """Reload configuration"""
    global config
    config = Config(config_file)
    return config
