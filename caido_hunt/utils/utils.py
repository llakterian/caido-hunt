#!/usr/bin/env python3
"""
utils.py - Enhanced utilities for caido-hunt with improved error handling and performance
"""
import os
import hashlib
import re
import logging
import time
import signal
import functools
from pathlib import Path
from contextlib import contextmanager
from typing import Optional, Dict, Any, List, Union
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

class TimeoutError(Exception):
    """Custom timeout exception"""
    pass

def timeout_handler(signum, frame):
    """Signal handler for timeout"""
    raise TimeoutError("Operation timed out")

@contextmanager
def timeout(seconds):
    """Context manager for timing out operations"""
    if seconds <= 0:
        yield
        return

    old_handler = signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(int(seconds))
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

def retry_request(func, *args, retries=3, backoff=1.0, backoff_multiplier=2.0, timeout=15, **kwargs):
    """
    Enhanced retry mechanism with exponential backoff and better error handling

    Args:
        func: Function to call
        *args: Positional arguments for func
        retries: Number of retry attempts
        backoff: Initial backoff time in seconds
        backoff_multiplier: Multiplier for backoff time
        timeout: Request timeout
        **kwargs: Keyword arguments for func

    Returns:
        Response object or raises exception
    """
    last_exception = None
    current_backoff = backoff

    for attempt in range(retries + 1):
        try:
            # Set timeout if not already specified
            if 'timeout' not in kwargs:
                kwargs['timeout'] = timeout

            response = func(*args, **kwargs)

            # Check for HTTP errors
            if hasattr(response, 'status_code'):
                if response.status_code >= 500:
                    raise requests.exceptions.HTTPError(f"Server error: {response.status_code}")
                elif response.status_code == 429:  # Rate limited
                    logger.warning(f"Rate limited, backing off for {current_backoff} seconds")
                    time.sleep(current_backoff)
                    current_backoff *= backoff_multiplier
                    continue

            return response

        except (requests.exceptions.RequestException,
                requests.exceptions.Timeout,
                requests.exceptions.ConnectionError,
                requests.exceptions.HTTPError) as e:
            last_exception = e

            if attempt == retries:
                logger.error(f"Request failed after {retries + 1} attempts: {e}")
                break

            logger.warning(f"Request failed (attempt {attempt + 1}/{retries + 1}), retrying in {current_backoff} seconds: {e}")
            time.sleep(current_backoff)
            current_backoff *= backoff_multiplier

        except Exception as e:
            # Non-recoverable error
            logger.error(f"Non-recoverable error in request: {e}")
            raise e

    raise last_exception

def create_session_with_retry(proxy=None, timeout=30, retries=3):
    """
    Create a requests session with automatic retry strategy

    Args:
        proxy: Proxy configuration dict
        timeout: Request timeout
        retries: Number of retries

    Returns:
        Configured requests.Session
    """
    session = requests.Session()

    # Configure retry strategy
    retry_strategy = Retry(
        total=retries,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE"],
        backoff_factor=1,
        raise_on_status=False
    )

    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    # Configure session
    if proxy:
        session.proxies.update(proxy)

    session.verify = False
    session.timeout = timeout
    session.headers.update({
        "User-Agent": "caido-hunt/2.1 (Security Scanner)"
    })

    return session

def safe_filename(s, max_length=200):
    """
    Convert string to safe filename with enhanced character handling

    Args:
        s: Input string
        max_length: Maximum filename length

    Returns:
        Safe filename string
    """
    if not s:
        return "unnamed"

    # Replace problematic characters
    safe = re.sub(r'[<>:"/\\|?*]', '_', s)
    safe = re.sub(r'[^\w\s\-._]', '_', safe)
    safe = re.sub(r'\s+', '_', safe)
    safe = re.sub(r'_+', '_', safe).strip('_')

    # Truncate if too long
    if len(safe) > max_length:
        safe = safe[:max_length].rstrip('_')

    # Ensure it's not empty
    return safe if safe else "unnamed"

def sha_digest(s, algorithm='sha1', length=10):
    """
    Generate hash digest with configurable algorithm and length

    Args:
        s: Input string
        algorithm: Hash algorithm (sha1, sha256, md5)
        length: Length of returned hash

    Returns:
        Hash digest string
    """
    if not isinstance(s, bytes):
        s = s.encode('utf-8')

    if algorithm == 'sha256':
        hash_obj = hashlib.sha256(s)
    elif algorithm == 'md5':
        hash_obj = hashlib.md5(s)
    else:  # Default to sha1
        hash_obj = hashlib.sha1(s)

    return hash_obj.hexdigest()[:length]

def load_cookies_from_file(session, path):
    """
    Enhanced cookie loading with better error handling and format support

    Args:
        session: requests.Session object
        path: Path to cookie file
    """
    if not os.path.exists(path):
        logger.error(f"Cookie file not found: {path}")
        return

    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        cookies_loaded = 0
        for line_num, line in enumerate(lines, 1):
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue

            # Support both key=value and JSON format
            if line.startswith('{'):
                try:
                    import json
                    cookie_data = json.loads(line)
                    for name, value in cookie_data.items():
                        session.cookies.set(name, str(value))
                        cookies_loaded += 1
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON format in cookie file line {line_num}: {line}")
            else:
                if "=" in line:
                    parts = line.split("=", 1)
                    if len(parts) == 2:
                        name, value = parts
                        session.cookies.set(name.strip(), value.strip())
                        cookies_loaded += 1
                    else:
                        logger.warning(f"Invalid cookie format in line {line_num}: {line}")

        logger.info(f"Loaded {cookies_loaded} cookies from {path}")

    except Exception as e:
        logger.error(f"Failed to load cookies from {path}: {e}")

class ScreenshotManager:
    """Enhanced screenshot manager with better driver management"""

    def __init__(self, geckodriver_path="./geckodriver", headless=True):
        self.geckodriver_path = geckodriver_path
        self.headless = headless
        self.driver = None

    def __enter__(self):
        self._init_driver()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._cleanup_driver()

    def _init_driver(self):
        """Initialize Firefox webdriver with optimal settings"""
        if self.driver:
            return

        try:
            options = Options()

            if self.headless:
                options.add_argument("--headless")

            # Performance and security options
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-gpu")
            options.add_argument("--disable-extensions")
            options.add_argument("--disable-plugins")
            options.add_argument("--disable-images")
            options.add_argument("--disable-javascript")

            # Set window size for consistent screenshots
            options.add_argument("--width=1920")
            options.add_argument("--height=1080")

            # Firefox-specific preferences
            options.set_preference("dom.webnotifications.enabled", False)
            options.set_preference("media.volume_scale", "0.0")
            options.set_preference("dom.push.enabled", False)
            options.set_preference("dom.webdriver.enabled", False)
            options.set_preference("useAutomationExtension", False)

            # Initialize driver
            self.driver = webdriver.Firefox(
                executable_path=self.geckodriver_path,
                options=options
            )

            # Set timeouts
            self.driver.set_page_load_timeout(30)
            self.driver.implicitly_wait(10)

            logger.info("WebDriver initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize WebDriver: {e}")
            self.driver = None
            raise

    def _cleanup_driver(self):
        """Safely cleanup WebDriver"""
        if self.driver:
            try:
                self.driver.quit()
                logger.info("WebDriver cleaned up successfully")
            except Exception as e:
                logger.warning(f"Error during WebDriver cleanup: {e}")
            finally:
                self.driver = None

    def configure_proxy(self, proxy_host, proxy_port):
        """Configure proxy for WebDriver"""
        if not self.driver:
            self._init_driver()

        try:
            # Configure Firefox proxy
            profile = webdriver.FirefoxProfile()
            profile.set_preference("network.proxy.type", 1)
            profile.set_preference("network.proxy.http", proxy_host)
            profile.set_preference("network.proxy.http_port", int(proxy_port))
            profile.set_preference("network.proxy.https", proxy_host)
            profile.set_preference("network.proxy.https_port", int(proxy_port))
            profile.set_preference("network.proxy.ssl", proxy_host)
            profile.set_preference("network.proxy.ssl_port", int(proxy_port))
            profile.update_preferences()

            logger.info(f"Proxy configured: {proxy_host}:{proxy_port}")

        except Exception as e:
            logger.error(f"Failed to configure proxy: {e}")

    def take_screenshot(self, url, output_path, wait_time=3):
        """
        Take screenshot of URL with enhanced error handling

        Args:
            url: URL to screenshot
            output_path: Path to save screenshot
            wait_time: Time to wait after page load

        Returns:
            bool: Success status
        """
        if not self.driver:
            self._init_driver()

        if not self.driver:
            logger.error("WebDriver not available for screenshot")
            return False

        try:
            # Ensure output directory exists
            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            # Navigate to URL
            logger.info(f"Taking screenshot of {url}")
            self.driver.get(url)

            # Wait for page to load
            time.sleep(wait_time)

            # Try to wait for body element to be present
            try:
                WebDriverWait(self.driver, 10).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )
            except TimeoutException:
                logger.warning(f"Page might not have loaded completely: {url}")

            # Take screenshot
            success = self.driver.save_screenshot(output_path)

            if success:
                logger.info(f"Screenshot saved: {output_path}")
                return True
            else:
                logger.error(f"Failed to save screenshot: {output_path}")
                return False

        except Exception as e:
            logger.error(f"Screenshot failed for {url}: {e}")
            return False

def take_screenshot_if_enabled(enabled, session, url, results_dir, geckodriver_path="./geckodriver"):
    """
    Enhanced screenshot function with better resource management

    Args:
        enabled: Whether screenshots are enabled
        session: requests.Session object
        url: URL to screenshot
        results_dir: Results directory
        geckodriver_path: Path to geckodriver executable

    Returns:
        Optional[str]: Path to screenshot file if successful
    """
    if not enabled or not url:
        return None

    try:
        # Create screenshot manager
        with ScreenshotManager(geckodriver_path, headless=True) as screenshot_mgr:

            # Configure proxy if session has one
            if session and hasattr(session, 'proxies') and session.proxies:
                proxy_url = session.proxies.get('http', '')
                if proxy_url.startswith('http://'):
                    proxy_parts = proxy_url.replace('http://', '').split(':')
                    if len(proxy_parts) == 2:
                        proxy_host, proxy_port = proxy_parts
                        screenshot_mgr.configure_proxy(proxy_host, proxy_port)

            # Generate output path
            safe_url = safe_filename(url)
            url_hash = sha_digest(url)
            screenshot_path = os.path.join(results_dir, "screenshots", f"{safe_url}_{url_hash}.png")

            # Take screenshot
            if screenshot_mgr.take_screenshot(url, screenshot_path):
                return screenshot_path
            else:
                return None

    except Exception as e:
        logger.error(f"Screenshot operation failed: {e}")
        return None

def validate_url(url):
    """
    Enhanced URL validation

    Args:
        url: URL to validate

    Returns:
        tuple: (is_valid, normalized_url, error_message)
    """
    if not url:
        return False, None, "URL is empty"

    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    # Basic URL pattern validation
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    if not url_pattern.match(url):
        return False, None, "Invalid URL format"

    return True, url, "URL is valid"

def ensure_directory_exists(path):
    """
    Ensure directory exists with proper error handling

    Args:
        path: Directory path to create

    Returns:
        bool: Success status
    """
    try:
        Path(path).mkdir(parents=True, exist_ok=True)
        return True
    except Exception as e:
        logger.error(f"Failed to create directory {path}: {e}")
        return False

def get_file_size_mb(file_path):
    """
    Get file size in MB

    Args:
        file_path: Path to file

    Returns:
        float: File size in MB
    """
    try:
        return os.path.getsize(file_path) / (1024 * 1024)
    except OSError:
        return 0.0

def truncate_text(text, max_length=1000, suffix="..."):
    """
    Safely truncate text with suffix

    Args:
        text: Text to truncate
        max_length: Maximum length
        suffix: Suffix to add when truncated

    Returns:
        str: Truncated text
    """
    if not text or len(text) <= max_length:
        return text

    return text[:max_length - len(suffix)] + suffix

def parse_content_type(content_type_header):
    """
    Parse Content-Type header

    Args:
        content_type_header: Content-Type header value

    Returns:
        tuple: (media_type, charset)
    """
    if not content_type_header:
        return "text/html", "utf-8"

    parts = content_type_header.split(';')
    media_type = parts[0].strip().lower()

    charset = "utf-8"
    for part in parts[1:]:
        if 'charset=' in part:
            charset = part.split('=')[1].strip()
            break

    return media_type, charset

def is_binary_content(content_type, url=None):
    """
    Check if content is binary based on content type and URL

    Args:
        content_type: Content-Type header value
        url: Optional URL for extension checking

    Returns:
        bool: True if content is likely binary
    """
    if not content_type:
        content_type = ""

    binary_types = [
        'image/', 'video/', 'audio/', 'application/pdf',
        'application/zip', 'application/octet-stream',
        'application/x-executable', 'application/x-binary'
    ]

    content_type_lower = content_type.lower()
    if any(bt in content_type_lower for bt in binary_types):
        return True

    # Check URL extension if provided
    if url:
        binary_extensions = {
            '.pdf', '.zip', '.rar', '.exe', '.bin', '.dmg',
            '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico',
            '.mp4', '.avi', '.mov', '.mp3', '.wav', '.flac',
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'
        }

        url_lower = url.lower()
        if any(ext in url_lower for ext in binary_extensions):
            return True

    return False

# Performance monitoring decorator
def monitor_performance(func):
    """Decorator to monitor function performance"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            duration = time.time() - start_time
            logger.debug(f"{func.__name__} completed in {duration:.3f}s")
            return result
        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"{func.__name__} failed after {duration:.3f}s: {e}")
            raise
    return wrapper

# Rate limiting decorator
def rate_limit(calls_per_second=1):
    """Decorator for rate limiting function calls"""
    min_interval = 1.0 / calls_per_second
    last_called = [0.0]

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            elapsed = time.time() - last_called[0]
            left_to_wait = min_interval - elapsed
            if left_to_wait > 0:
                time.sleep(left_to_wait)
            ret = func(*args, **kwargs)
            last_called[0] = time.time()
            return ret
        return wrapper
    return decorator
