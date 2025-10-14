#!/usr/bin/env python3
"""
scanner_core.py - Enhanced crawl, discover, and call plugin modules for active testing.
"""
import os, time, json, re, threading, logging, heapq
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from bs4 import BeautifulSoup
import tldextract
import warnings
import itertools
import heapq
import urllib.parse
from xml.etree import ElementTree
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
from utils import (safe_filename, sha_digest, load_cookies_from_file, take_screenshot_if_enabled,
                   retry_request, create_session_with_retry, validate_url, ensure_directory_exists,
                   monitor_performance, ScreenshotManager)
from reporter import Reporter
from config import get_config
import urllib.parse
from selenium import webdriver
from selenium.webdriver.firefox.options import Options


MODULES_DIR = "modules"

class ScannerCore:
    def __init__(self, root, proxy=None, depth=None, max_pages=None, workers=None, sleep=None,
                 cookie_file=None, login_url=None, login_data=None, denylist_file=None, screenshot=None,
                 elk_url=None, bounty_url=None, ai_api_key=None, gui=None, headless=None, filter_high_impact=None):
        # Load configuration
        self.config = get_config()

        # Validate and normalize target URL
        is_valid, normalized_url, error_msg = validate_url(root)
        if not is_valid:
            raise ValueError(f"Invalid target URL: {error_msg}")
        self.root = normalized_url

        # Initialize configuration with defaults and overrides
        self.proxy_url = proxy or self.config.get('proxy.default_url')
        if self.proxy_url:
            self.proxy = {"http": self.proxy_url, "https": self.proxy_url}
            proxy_parts = self.proxy_url.split("://")[1].split(":")
            self.proxy_host = proxy_parts[0]
            self.proxy_port = int(proxy_parts[1]) if len(proxy_parts) > 1 else 8080
        else:
            self.proxy = None
            self.proxy_host = None
            self.proxy_port = None

        self.depth = depth if depth is not None else self.config.get('crawler.default_depth')
        self.max_pages = max_pages if max_pages is not None else self.config.get('crawler.max_pages')
        self.workers = workers if workers is not None else self.config.get('crawler.workers')
        self.sleep = sleep if sleep is not None else self.config.get('crawler.sleep_between_requests')

        # Create enhanced session with retry strategy
        self.session = create_session_with_retry(
            proxy=self.proxy,
            timeout=self.config.get('crawler.request_timeout'),
            retries=self.config.get('crawler.max_retries')
        )
        # Thread-safe collections
        self.visited = set()
        self.lock = threading.Lock()
        self.visited_lock = threading.Lock()
        self.cache_lock = threading.Lock()
        self.response_cache = {}
        self.frontier = []
        self.frontier_lock = threading.Lock()
        self.frontier_seen = set()
        self._frontier_counter = itertools.count()
        self.scope_domain = tldextract.extract(self.root).registered_domain
        self.forms_index = {}
        self.asset_cache = set()
        self.site_metadata = {"servers": set(), "powered_by": set(), "frameworks": set()}
        self.framework_keywords = ["wordpress", "drupal", "joomla", "next.js", "nuxt", "react", "angular", "vue", "laravel", "rails", "django", "express", "spring", "symfony", "flask", "asp.net"]
        self.max_depth = max(self.depth, 4)
        self.pages = 0

        # Enhanced directory management
        self.results_dir = self._make_results_dir()
        self.raw_req_dir = os.path.join(self.results_dir, "raw-requests")
        self.raw_res_dir = os.path.join(self.results_dir, "raw-responses")
        ensure_directory_exists(self.raw_req_dir)
        ensure_directory_exists(self.raw_res_dir)

        # Configuration overrides
        self.screenshot = screenshot if screenshot is not None else self.config.get('scanner.enable_screenshots')
        self.gui = gui if gui is not None else self.config.get('gui.enabled')
        self.headless = headless if headless is not None else self.config.get('scanner.headless_browser')
        self.script_endpoint_regex = re.compile(r"['\"](/[^'\"\\s?#]+(?:\\?[^'\"#]*)?)['\"]")
        self.full_url_regex = re.compile(r"https?://[^\\s'\"<>]+", re.I)
        self.asset_blacklist = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.css', '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.zip', '.rar', '.mp4', '.mp3', '.avi', '.flv', '.wmv', '.mov'}
        self.script_extensions = {'.js', '.mjs', '.ts', '.tsx', '.jsx'}
        self.discovery_words = ["admin", "login", "signin", "signup", "account", "user", "profile", "settings", "dashboard", "manage", "portal", "control", "console", "api", "graphql", "rest", "debug", "test", "dev", "beta", "stage", "backup", "old", "archive", "internal", "private", "payments", "checkout", "cart", "order", "invoice", "upload", "download", "report", "stats", "metrics", "status", "health", "ping", "config", "system", "docs", "swagger", "openapi", "redoc", "graphiql"]

        # Enhanced denylist management
        self.denylist = []
        if denylist_file and os.path.exists(denylist_file):
            try:
                with open(denylist_file, "r", encoding="utf-8") as f:
                    for ln in f:
                        ln = ln.strip()
                        if ln and not ln.startswith('#'):
                            self.denylist.append(re.compile(ln, re.I))
                logger.info(f"Loaded {len(self.denylist)} denylist patterns from {denylist_file}")
            except Exception as e:
                logger.error(f"Failed to load denylist file {denylist_file}: {e}")
                self.denylist = self.config.get_denylist_patterns()
        else:
            self.denylist = self.config.get_denylist_patterns()
            logger.info(f"Using default denylist with {len(self.denylist)} patterns")

        # Enhanced authentication handling
        if cookie_file:
            load_cookies_from_file(self.session, cookie_file)
        elif login_url and login_data:
            try:
                login_payload = json.loads(login_data) if isinstance(login_data, str) else login_data
                response = retry_request(
                    self.session.post,
                    login_url,
                    data=login_payload,
                    timeout=self.config.get('crawler.request_timeout')
                )
                if response.status_code == 200:
                    logger.info("Login successful")
                else:
                    logger.warning(f"Login returned status code: {response.status_code}")
            except Exception as e:
                logger.error(f"Login failed: {e}")

        # Load vulnerability modules
        self.modules = self._load_modules()

        # Bootstrap target surface discovery
        self._bootstrap_target_surface()

        # Initialize GUI with enhanced configuration
        if self.gui:
            import gui
            self.gui_manager = gui.GUIManager(
                host=self.config.get('gui.host'),
                port=self.config.get('gui.port'),
                debug=self.config.get('gui.debug')
            )
        else:
            self.gui_manager = None

        # Initialize enhanced reporter
        filter_high_impact_final = filter_high_impact if filter_high_impact is not None else self.config.get('reporting.filter_high_impact_only')
        ai_api_key_final = ai_api_key or self.config.get('reporting.openai_api_key')
        elk_url_final = elk_url or self.config.get('reporting.elk_url')
        bounty_url_final = bounty_url or self.config.get('reporting.bounty_webhook')

        self.reporter = Reporter(
            self.results_dir,
            elk_url_final,
            self.gui_manager,
            bounty_url_final,
            ai_api_key_final,
            filter_high_impact_final
        )

        if self.gui_manager:
            self.gui_manager.socketio.emit('scan_start', {
                'max_pages': self.max_pages,
                'target': self.root,
                'config': {
                    'depth': self.depth,
                    'workers': self.workers,
                    'proxy': self.proxy_url
                }
            })

        # AI-Powered Detection Integration
        self.ai_analysis_enabled = self.config.get('reporting.ai_analysis')
        if ai_api_key_final and self.ai_analysis_enabled:
            self.ai_model = self._initialize_ai_model(ai_api_key_final)
        else:
            self.ai_model = None

        # Enhanced parallelization
        self.executor = ThreadPoolExecutor(max_workers=self.workers)
        self.cache = {}

        # Screenshot manager
        self.screenshot_manager = None
        if self.screenshot:
            geckodriver_path = self.config.get('paths.geckodriver')
            self.screenshot_manager = ScreenshotManager(geckodriver_path, self.headless)

        logger.info(f"Scanner initialized - Target: {self.root}, Workers: {self.workers}, Max Pages: {self.max_pages}")

    def _make_results_dir(self):
        base_domain = tldextract.extract(self.root).registered_domain or "target"
        ts = time.strftime("%Y%m%d_%H%M%S")
        results_base = self.config.get('paths.results_dir', './caido_results')
        path = os.path.join(results_base, f"{base_domain}_{ts}")
        ensure_directory_exists(path)
        logger.info(f"Results directory: {path}")
        return path

    @monitor_performance
    def _load_modules(self):
        modules = []
        modules_dir = self.config.get('paths.modules_dir', MODULES_DIR)

        if not os.path.isdir(modules_dir):
            logger.warning(f"Modules directory not found: {modules_dir}")
            return modules

        import importlib.util, glob
        files = glob.glob(os.path.join(modules_dir, "*.py"))

        for f in files:
            name = os.path.splitext(os.path.basename(f))[0]
            if name == "__init__":
                continue

            try:
                spec = importlib.util.spec_from_file_location(name, f)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)

                # Module must implement 'register' function returning a dict describing hooks
                if hasattr(mod, "register"):
                    module_config = mod.register()
                    if isinstance(module_config, dict) and 'name' in module_config:
                        modules.append(module_config)
                        logger.info(f"Module loaded: {name} ({module_config.get('name')})")
                    else:
                        logger.warning(f"Module {name} returned invalid configuration")
                else:
                    logger.warning(f"Module {name} missing register() function - skipping")

            except Exception as e:
                logger.error(f"Failed to load module {name}: {e}")

        logger.info(f"Loaded {len(modules)} vulnerability detection modules")
        return modules

    def _is_denied(self, url):
        for rx in self.denylist:
            if rx.search(url):
                return True
        return False

    def _bootstrap_target_surface(self):
        """Initialize the frontier with the root URL and perform initial discovery"""
        logger.info("Bootstrapping target surface discovery")

        # Initialize frontier with root URL
        self._queue_candidate(self.root, 0, priority=0)

        # Try to discover common endpoints
        parsed_root = urllib.parse.urlparse(self.root)
        base_url = f"{parsed_root.scheme}://{parsed_root.netloc}"

        # Common discovery paths with lower priority
        common_paths = ["/robots.txt", "/sitemap.xml", "/sitemap_index.xml", "/.well-known/security.txt"]
        for path in common_paths:
            candidate_url = base_url + path
            self._queue_candidate(candidate_url, 0, priority=10)

        # Add discovery words as potential endpoints (very low priority)
        for word in self.discovery_words[:20]:  # Limit to first 20 to avoid flooding
            for ext in ["", "/", ".html", ".php", ".jsp", ".asp"]:
                candidate_url = f"{base_url}/{word}{ext}"
                self._queue_candidate(candidate_url, 1, priority=20)

        logger.info(f"Bootstrap complete. Frontier size: {len(self.frontier)}")

    def _queue_candidate(self, url, depth, priority=10):
        """Add a candidate URL to the frontier with priority"""
        if not url:
            return

        # Normalize URL
        try:
            parsed = urllib.parse.urlparse(url)
            if not parsed.scheme:
                # Relative URL, make it absolute
                url = urllib.parse.urljoin(self.root, url)
                parsed = urllib.parse.urlparse(url)

            # Clean up the URL
            normalized_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                normalized_url += f"?{parsed.query}"

        except Exception as e:
            logger.debug(f"Failed to parse URL {url}: {e}")
            return

        # Check if already processed
        with self.visited_lock:
            if normalized_url in self.visited:
                return

        with self.frontier_lock:
            if normalized_url in self.frontier_seen:
                return

            # Check scope
            try:
                candidate_domain = tldextract.extract(normalized_url).registered_domain
                if candidate_domain != self.scope_domain:
                    return
            except Exception:
                return

            # Add to frontier with priority (lower number = higher priority)
            counter = next(self._frontier_counter)
            heapq.heappush(self.frontier, (priority, counter, normalized_url, depth))
            self.frontier_seen.add(normalized_url)

        logger.debug(f"Queued: {normalized_url} (depth: {depth}, priority: {priority})")

    def _pop_frontier(self):
        """Pop the highest priority item from the frontier"""
        with self.frontier_lock:
            if not self.frontier:
                return None

            try:
                priority, counter, url, depth = heapq.heappop(self.frontier)
                self.frontier_seen.discard(url)
                return (url, depth)
            except (IndexError, ValueError):
                return None

    def _record_site_metadata(self, response):
        """Record metadata about the target site from HTTP responses"""
        if not response or not hasattr(response, 'headers'):
            return

        headers = response.headers

        # Record server information
        server = headers.get('Server', '').lower()
        if server:
            self.site_metadata["servers"].add(server)

        # Record powered-by information
        powered_by = headers.get('X-Powered-By', '').lower()
        if powered_by:
            self.site_metadata["powered_by"].add(powered_by)

        # Detect frameworks from headers and content
        if hasattr(response, 'text'):
            content_lower = response.text.lower()
            for framework in self.framework_keywords:
                if framework in content_lower:
                    self.site_metadata["frameworks"].add(framework)

        # Record other interesting headers
        for header_name in ['X-Generator', 'X-Drupal-Cache', 'X-Powered-CMS']:
            header_value = headers.get(header_name, '').lower()
            if header_value:
                self.site_metadata["frameworks"].add(f"{header_name}: {header_value}")

        logger.debug(f"Site metadata updated: {dict(self.site_metadata)}")

    def run(self, disable_active=False):
        logger.info(f"Starting crawl: {self.root}")
        with ThreadPoolExecutor(max_workers=self.workers) as crawl_pool:
            in_flight = {}
            while self.pages < self.max_pages:
                while len(in_flight) < self.workers:
                    next_task = self._pop_frontier()
                    if not next_task:
                        break
                    url, depth = next_task
                    if self._is_denied(url):
                        with self.visited_lock:
                            self.visited.add(url)
                        continue
                    future = crawl_pool.submit(self._fetch_and_process, url, depth)
                    in_flight[future] = (url, depth)
                if not in_flight:
                    with self.frontier_lock:
                        if not self.frontier:
                            break
                    time.sleep(0.1)
                    continue
                try:
                    done_future = next(as_completed(list(in_flight.keys())))
                except StopIteration:
                    break
                in_flight.pop(done_future, None)
                try:
                    done_future.result()
                except Exception as e:
                    logger.error(f"Fetch task error: {e}")

        logger.info(f"Discovery done. Pages: {self.pages}. Running active modules..." if not disable_active else "Discovery done. Active disabled.")
        if not disable_active:
            self._run_active()
        logger.info(f"Scan finished. Results: {self.results_dir}")
        if self.gui_manager:
            self.gui_manager.socketio.emit('scan_end', {'pages': self.pages})

    def _fetch_and_process(self, url, depth):
        with self.visited_lock:
            if url in self.visited:
                return
            self.visited.add(url)
        try:
            resp = retry_request(self.session.get, url, timeout=20, allow_redirects=True)
        except Exception as e:
            logger.error(f"Fetch error {url}: {e}")
            return
        with self.lock:
            self.pages += 1
        self._save_raw(url, resp)
        logger.info(f"Fetched ({self.pages}): {url} [{resp.status_code}]")
        if self.gui_manager:
            self.gui_manager.socketio.emit('progress', {'pages': self.pages, 'max_pages': self.max_pages})
        self._record_site_metadata(resp)
        if not (200 <= resp.status_code < 300):
            logger.warning(f"Non-2xx status {resp.status_code} for {url}, skipping processing")
            time.sleep(self.sleep)
            return
        cl = resp.headers.get("Content-Length")
        if cl and int(cl) > 10 * 1024 * 1024:
            logger.warning(f"Skipping large file ({int(cl)//1024//1024}MB): {url}")
            time.sleep(self.sleep)
            return
        ct = resp.headers.get("Content-Type","")
        if "html" in ct.lower():
            if self.headless:
                try:
                    soup = self._get_soup_headless(url)
                except Exception as e:
                    logger.warning(f"Headless failed for {url}: {e}, falling back to static parsing")
                    soup = BeautifulSoup(resp.text, "html.parser")
            else:
                soup = BeautifulSoup(resp.text, "html.parser")
            self._collect_from_page(url, soup, depth)
        else:
            self._collect_from_non_html(url, resp, depth)
        time.sleep(self.sleep)

    def _collect_from_page(self, url, soup, depth):
        """Extract links and forms from HTML pages"""
        if depth < self.max_depth:
            self._enqueue_links(url, soup, depth)

        # Save forms for later analysis
        self._save_forms(url, soup)

        # Extract and cache JavaScript endpoints
        for script in soup.find_all('script'):
            if script.get('src'):
                script_url = urllib.parse.urljoin(url, script.get('src'))
                if any(script_url.lower().endswith(ext) for ext in self.script_extensions):
                    self.asset_cache.add(script_url)
            elif script.string:
                # Extract endpoints from inline JavaScript
                for match in self.script_endpoint_regex.finditer(script.string):
                    endpoint = match.group(1)
                    full_endpoint = urllib.parse.urljoin(url, endpoint)
                    if depth < self.max_depth - 1:
                        self._queue_candidate(full_endpoint, depth + 1, priority=8)

    def _collect_from_non_html(self, url, resp, depth):
        """Extract information from non-HTML responses"""
        content_type = resp.headers.get('Content-Type', '').lower()

        # Handle robots.txt
        if url.endswith('/robots.txt') and resp.status_code == 200:
            for line in resp.text.split('\n'):
                line = line.strip()
                if line.startswith('Disallow:') or line.startswith('Allow:'):
                    path = line.split(':', 1)[1].strip()
                    if path and path != '/' and not path.startswith('*'):
                        candidate_url = urllib.parse.urljoin(url, path)
                        if depth < self.max_depth:
                            self._queue_candidate(candidate_url, depth + 1, priority=12)
                elif line.startswith('Sitemap:'):
                    sitemap_url = line.split(':', 1)[1].strip()
                    if depth < self.max_depth:
                        self._queue_candidate(sitemap_url, depth + 1, priority=5)

        # Handle XML sitemaps
        elif ('xml' in content_type or url.endswith('.xml')) and resp.status_code == 200:
            try:
                # Try to parse as XML and extract URLs
                import xml.etree.ElementTree as ET
                root = ET.fromstring(resp.text)

                # Look for sitemap URLs
                for elem in root.iter():
                    if elem.tag.endswith('loc') and elem.text:
                        candidate_url = elem.text.strip()
                        if candidate_url.startswith('http') and depth < self.max_depth:
                            self._queue_candidate(candidate_url, depth + 1, priority=6)
            except Exception as e:
                logger.debug(f"Failed to parse XML from {url}: {e}")

        # Handle JavaScript files
        elif ('javascript' in content_type or url.endswith('.js')) and resp.status_code == 200:
            # Extract URLs from JavaScript
            for match in self.full_url_regex.finditer(resp.text):
                js_url = match.group(0)
                try:
                    parsed = urllib.parse.urlparse(js_url)
                    if parsed.netloc == urllib.parse.urlparse(url).netloc and depth < self.max_depth:
                        self._queue_candidate(js_url, depth + 1, priority=9)
                except Exception:
                    continue

            # Extract relative endpoints
            for match in self.script_endpoint_regex.finditer(resp.text):
                endpoint = match.group(1)
                full_endpoint = urllib.parse.urljoin(url, endpoint)
                if depth < self.max_depth - 1:
                    self._queue_candidate(full_endpoint, depth + 1, priority=10)

    def _save_raw(self, url, resp):
        req = resp.request
        rfn = safe_filename(url)+"_"+sha_digest(url)+".req.txt"
        with open(os.path.join(self.raw_req_dir, rfn),"w",encoding="utf-8") as f:
            try:
                f.write(f"{req.method} {req.path_url} HTTP/1.1\n")
                for k,v in req.headers.items():
                    f.write(f"{k}: {v}\n")
                if req.body:
                    f.write("\n")
                    f.write(req.body.decode() if isinstance(req.body,(bytes,bytearray)) else str(req.body))
            except Exception:
                f.write("<could not render request>")
        rfn2 = safe_filename(url)+"_"+sha_digest(url)+".resp.txt"
        with open(os.path.join(self.raw_res_dir, rfn2),"w",encoding="utf-8") as f:
            try:
                f.write(f"HTTP/1.1 {resp.status_code}\n")
                for k,v in resp.headers.items():
                    f.write(f"{k}: {v}\n")
                f.write("\n")
                f.write(resp.text)
            except Exception:
                f.write("<binary or unreadable response>")

    def _enqueue_links(self, base, soup, depth):
        # Skip common asset extensions to avoid crawling images, scripts, styles, etc.
        skip_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.css', '.js', '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.zip', '.rar', '.mp4', '.mp3', '.avi', '.flv', '.wmv', '.mov'}
        links_found = 0
        for tag in soup.find_all(['a','link','script','img','form']):
            href = tag.get('href') or tag.get('action') or tag.get('src')
            if not href: continue
            full = urllib.parse.urljoin(base, href.split('#',1)[0])
            if tldextract.extract(full).registered_domain == tldextract.extract(self.root).registered_domain:
                # Skip assets
                if any(full.lower().endswith(ext) for ext in skip_extensions):
                    continue
                # Use new frontier system with appropriate priority based on depth
                priority = min(depth + 5, 15)  # Higher depth = lower priority
                self._queue_candidate(full, depth + 1, priority=priority)
                links_found += 1
        logger.debug(f"Enqueued {links_found} links from {base}")

    def _save_forms(self, base, soup):
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action") or base
            method = (form.get("method") or "GET").upper()
            inputs = {}
            for inp in form.find_all(["input","textarea","select"]):
                name = inp.get("name")
                if not name: continue
                val = inp.get("value") or ""
                inputs[name] = val
            forms.append({"action": urllib.parse.urljoin(base, action), "method": method, "inputs": inputs})
        if forms:
            fn = os.path.join(self.results_dir, f"forms_{safe_filename(base)}.json")
            with open(fn,"w",encoding="utf-8") as f:
                json.dump(forms,f,indent=2)
            logger.info(f"Saved {len(forms)} forms -> {fn}")

    def _get_soup_headless(self, url):
        options = Options()
        options.add_argument("--headless")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.set_preference("network.proxy.type", 1)
        options.set_preference("network.proxy.http", self.proxy_host)
        options.set_preference("network.proxy.http_port", self.proxy_port)
        options.set_preference("network.proxy.ssl", self.proxy_host)
        options.set_preference("network.proxy.ssl_port", self.proxy_port)
        driver = webdriver.Firefox(options=options)
        driver.set_page_load_timeout(30)
        try:
            driver.get(url)
            soup = BeautifulSoup(driver.page_source, "html.parser")
        finally:
            driver.quit()
        return soup

    def _run_active(self):
        tasks = []
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            # parameters in visited URLs
            for url in list(self.visited):
                if self._is_denied(url): continue
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                if qs:
                    for param in qs.keys():
                        # schedule module param tests
                        for mod in self.modules:
                            if 'param_test' in mod:
                                tasks.append(pool.submit(mod['param_test'], url, param, self.session, self))
                # schedule form tests
                formfile = os.path.join(self.results_dir, f"forms_{safe_filename(url)}.json")
                if os.path.exists(formfile):
                    with open(formfile,"r",encoding="utf-8") as f:
                        forms = json.load(f)
                    for form in forms:
                        for mod in self.modules:
                            if 'form_test' in mod:
                                tasks.append(pool.submit(mod['form_test'], form, self.session, self))
            # wait
            for fut in as_completed(tasks):
                try:
                    res = fut.result()
                    if res and isinstance(res, dict):
                        # module returns dict for a finding
                        logger.info(f"Finding: {res.get('title', 'Unknown vulnerability')} at {res.get('url', 'Unknown URL')}")
                        self.reporter.record_finding(res)
                        # optionally take screenshot
                        take_screenshot_if_enabled(self.screenshot, self.session, res.get("evidence_url"), self.results_dir)
                except Exception as e:
                    logger.error(f"Active task error: {e}")

    def _initialize_ai_model(self, api_key):
        # Placeholder for AI model initialization
        logger.info("Initializing AI model with provided API key.")
        return None  # Replace with actual AI model initialization

    def _fetch_with_cache(self, url):
        """Fetch a URL with caching to avoid redundant requests."""
        if url in self.cache:
            return self.cache[url]
        response = retry_request(self.session.get, url, timeout=15)
        self.cache[url] = response
        return response

    def run_nuclei_scans(self, targets_file):
        """Run nuclei scans with predefined AI queries."""
        queries = [
            "Find exposed AI/ML model files (.pkl, .h5, .pt) that may leak proprietary algorithms or sensitive training data",
            "Find exposed automation scripts (.sh, .ps1, .bat) revealing internal tooling or credentials",
            "Identify misconfigured CSP headers allowing 'unsafe-inline' or wildcard sources",
            "Detect pages leaking JWT tokens in URLs or cookies",
            "Identify overly verbose error messages revealing framework or library details",
            "Find application endpoints with verbose stack traces or source code exposure",
            "Find sensitive information in HTML comments (debug notes, API keys, credentials)",
            "Find exposed .env files leaking credentials, API keys, and database passwords",
            "Find exposed configuration files such as config.json, config.yaml, config.php, application.properties containing API keys and database credentials.",
            "Find exposed configuration files containing sensitive information such as credentials, API keys, database passwords, and cloud service secrets.",
            "Find database configuration files such as database.yml, db_config.php, .pgpass, .my.cnf leaking credentials.",
            "Find exposed Docker and Kubernetes configuration files such as docker-compose.yml, kubeconfig, .dockercfg, .docker/config.json containing cloud credentials and secrets.",
            "Find exposed SSH keys and configuration files such as id_rsa, authorized_keys, and ssh_config.",
            "Find exposed WordPress configuration files (wp-config.php) containing database credentials and authentication secrets.",
            "Identify exposed .npmrc and .yarnrc files leaking NPM authentication tokens",
            "Identify open directory listings exposing sensitive files",
            "Find exposed .git directories allowing full repo download",
            "Find exposed .svn and .hg repositories leaking source code",
            "Identify open FTP servers allowing anonymous access",
            "Find GraphQL endpoints with introspection enabled",
            "Identify exposed .well-known directories revealing sensitive data",
            "Find publicly accessible phpinfo() pages leaking environment details",
            "Find exposed Swagger, Redocly, GraphiQL, and API Blueprint documentation",
            "Identify exposed .vscode and .idea directories leaking developer configs",
            "Detect internal IP addresses (10.x.x.x, 192.168.x.x, etc.) in HTTP responses",
            "Find exposed WordPress debug.log files leaking credentials and error messages",
            "Detect misconfigured CORS allowing wildcard origins ('*')",
            "Find publicly accessible backup and log files (.log, .bak, .sql, .zip, .dump)",
            "Find exposed admin panels with default credentials",
            "Identify commonly used API endpoints that expose sensitive user data, returning HTTP status 200 OK.",
            "Detect web applications running in debug mode, potentially exposing sensitive system information."
        ]

        for query in queries:
            logger.info(f"Running nuclei with query: {query}")
            if self.gui_manager:
                self.gui_manager.socketio.emit('nuclei_scan_start', {'query': query})

            # Execute nuclei command
            cmd = f"nuclei -list {targets_file} -ai \"{query}\""
            os.system(cmd)

            if self.gui_manager:
                self.gui_manager.socketio.emit('nuclei_scan_complete', {'query': query})

            logger.info(f"Completed nuclei scan for query: {query}")
