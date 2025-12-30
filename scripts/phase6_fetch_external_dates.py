"""
Phase 6: Fetch external dates for responsiveness analysis
Goal: Extract and fetch dates for:
- MITRE ATT&CK technique release/update dates
- CVE publication dates (NVD)
- Threat report publication dates (CISA, Mandiant, etc.)

Features:
- Multi-threaded HTTP fetching
- Selenium for JS-rendered pages
- NVD API key support for faster CVE fetching
"""
import sqlite3
import json
import re
import requests
import time
import os
from pathlib import Path
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import logging
import sys
from urllib.parse import urlparse
from typing import List, Dict, Optional, Set

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    env_path = Path('.env')
    if not env_path.exists():
        env_path = Path(__file__).parent.parent / '.env'
    load_dotenv(env_path)
except ImportError:
    pass

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('phase6_fetch_external_dates.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Configuration
MAX_WORKERS = 10  # Parallel HTTP workers
NVD_API_DELAY = 6.0  # NVD API: 5 requests per 30 seconds without key (~0.17 req/sec)
NVD_API_DELAY_WITH_KEY = 0.6  # With API key: 50 requests per 30 seconds (~1.67 req/sec)
ATTACK_API_DELAY = 0.1
NVD_API_KEY = os.environ.get('NVD_API_KEY')

# Selenium driver pool for parallel fetching
_selenium_drivers = []
_selenium_lock = None
_chrome_service = None


def get_utc_now() -> str:
    """Get current UTC time as ISO string."""
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def _create_chrome_driver():
    """Create a new headless Chrome driver."""
    global _chrome_service
    
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    
    # Cache the service to avoid re-downloading driver
    if _chrome_service is None:
        try:
            from webdriver_manager.chrome import ChromeDriverManager
            _chrome_service = Service(ChromeDriverManager().install())
        except Exception:
            _chrome_service = Service()
    
    options = Options()
    options.add_argument('--headless')
    options.add_argument('--disable-gpu')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--window-size=1920,1080')
    options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0')
    options.add_argument('--log-level=3')
    options.add_experimental_option('excludeSwitches', ['enable-logging'])
    
    driver = webdriver.Chrome(service=_chrome_service, options=options)
    driver.set_page_load_timeout(15)
    return driver


def init_selenium_pool(num_drivers: int = 4):
    """Initialize a pool of Selenium drivers for parallel fetching."""
    global _selenium_drivers, _selenium_lock
    
    import threading
    _selenium_lock = threading.Lock()
    
    logger.info(f"Initializing {num_drivers} Selenium Chrome drivers...")
    
    for i in range(num_drivers):
        try:
            driver = _create_chrome_driver()
            _selenium_drivers.append(driver)
            logger.info(f"  Driver {i+1}/{num_drivers} initialized")
        except Exception as e:
            logger.warning(f"  Failed to create driver {i+1}: {e}")
            break
    
    logger.info(f"Selenium pool ready: {len(_selenium_drivers)} drivers")
    return len(_selenium_drivers) > 0


def get_selenium_driver():
    """Get a driver from the pool (blocking if none available)."""
    global _selenium_drivers, _selenium_lock
    
    if not _selenium_drivers:
        # Fallback: try to create a single driver
        try:
            driver = _create_chrome_driver()
            return driver
        except Exception as e:
            logger.warning(f"Could not create Selenium driver: {e}")
            return None
    
    # Wait for available driver
    while True:
        with _selenium_lock:
            if _selenium_drivers:
                return _selenium_drivers.pop()
        time.sleep(0.1)


def return_selenium_driver(driver):
    """Return a driver to the pool."""
    global _selenium_drivers, _selenium_lock
    
    if driver is None:
        return
    
    if _selenium_lock:
        with _selenium_lock:
            _selenium_drivers.append(driver)
    else:
        _selenium_drivers.append(driver)


def close_selenium_drivers():
    """Close all Selenium drivers in the pool."""
    global _selenium_drivers
    
    for driver in _selenium_drivers:
        try:
            driver.quit()
        except:
            pass
    
    _selenium_drivers = []
    logger.info("Selenium drivers closed")


# ============================================================
# EXTRACTION FUNCTIONS
# ============================================================

def extract_attack_techniques(tags_json: str) -> Set[str]:
    """Extract ATT&CK technique IDs from tags JSON."""
    if not tags_json:
        return set()
    
    try:
        tags = json.loads(tags_json) if isinstance(tags_json, str) else tags_json
        if not isinstance(tags, list):
            return set()
        
        techniques = set()
        for tag in tags:
            if not isinstance(tag, str):
                continue
            
            match = re.search(r'attack\.t?(\d{4,5})', tag, re.IGNORECASE)
            if match:
                techniques.add(f"T{match.group(1)}")
            
            match = re.search(r'attack-t(\d{4,5})', tag, re.IGNORECASE)
            if match:
                techniques.add(f"T{match.group(1)}")
        
        return techniques
    except Exception as e:
        logger.debug(f"Error parsing tags: {e}")
        return set()


def extract_cves(references_json: str) -> Set[str]:
    """Extract CVE IDs from references JSON."""
    if not references_json:
        return set()
    
    try:
        references = json.loads(references_json) if isinstance(references_json, str) else references_json
        if not isinstance(references, list):
            return set()
        
        cves = set()
        for ref in references:
            if not isinstance(ref, str):
                continue
            matches = re.findall(r'CVE-\d{4}-\d{4,}', ref, re.IGNORECASE)
            cves.update(m.upper() for m in matches)
        
        return cves
    except Exception as e:
        logger.debug(f"Error parsing references: {e}")
        return set()


def extract_threat_report_urls(references_json: str) -> List[Dict[str, str]]:
    """Extract threat report URLs from known sources."""
    if not references_json:
        return []
    
    try:
        references = json.loads(references_json) if isinstance(references_json, str) else references_json
        if not isinstance(references, list):
            return []
        
        report_urls = []
        known_domains = [
            'cisa.gov', 'us-cert.gov', 'mandiant.com', 'fireeye.com',
            'crowdstrike.com', 'microsoft.com/security', 'securelist.com',
            'talosintelligence.com', 'unit42.paloaltonetworks.com',
            'blog.talosintelligence.com', 'symantec.com/blogs',
            'trendmicro.com', 'proofpoint.com', 'sentinelone.com',
            'recordedfuture.com', 'dragos.com',
        ]
        
        for ref in references:
            if not isinstance(ref, str) or not ref.startswith('http'):
                continue
            
            try:
                parsed = urlparse(ref)
                domain = parsed.netloc.lower()
                
                for known_domain in known_domains:
                    if known_domain in domain:
                        report_urls.append({
                            'url': ref,
                            'domain': domain,
                            'source': known_domain.split('.')[0]
                        })
                        break
            except Exception:
                continue
        
        return report_urls
    except Exception as e:
        logger.debug(f"Error parsing references: {e}")
        return []


# ============================================================
# DATE EXTRACTION FROM HTML
# ============================================================

def extract_date_from_url(url: str) -> Optional[str]:
    """Extract date from URL patterns only (no HTTP request)."""
    url_date_patterns = [
        r'/(\d{4})/(\d{2})/(\d{2})/',
        r'/(\d{4})-(\d{2})-(\d{2})/',
        r'/(\d{4})/(\d{2})/(\d{2})-',
        r'-(\d{4})-(\d{2})-(\d{2})',
        r'_(\d{4})(\d{2})(\d{2})',
        r'/(\d{4})/(\d{2})/',
        r'/research/(\d{2})/([a-z])/',
        r'/(\d{4})/([a-z]{3})/',
    ]
    
    month_letter_map = {'a': 1, 'b': 2, 'c': 3, 'd': 4, 'e': 5, 'f': 6,
                        'g': 7, 'h': 8, 'i': 9, 'j': 10, 'k': 11, 'l': 12}
    month_name_map = {'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6,
                      'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12}
    
    for pattern in url_date_patterns:
        match = re.search(pattern, url, re.IGNORECASE)
        if match:
            groups = match.groups()
            try:
                if len(groups) == 3:
                    year, month, day = groups
                    year = int(year)
                    if year < 100:
                        year = 2000 + year
                    month = int(month)
                    day = int(day)
                    if 2000 <= year <= 2100 and 1 <= month <= 12 and 1 <= day <= 31:
                        return f"{year:04d}-{month:02d}-{day:02d}T00:00:00Z"
                elif len(groups) == 2:
                    year, month = groups
                    year = int(year)
                    if year < 100:
                        year = 2000 + year
                    if month.isalpha():
                        if len(month) == 1:
                            month = month_letter_map.get(month.lower(), 0)
                        else:
                            month = month_name_map.get(month.lower()[:3], 0)
                    else:
                        month = int(month)
                    if 2000 <= year <= 2100 and 1 <= month <= 12:
                        return f"{year:04d}-{month:02d}-01T00:00:00Z"
            except (ValueError, TypeError):
                continue
    return None


def extract_date_from_html(html: str) -> Optional[str]:
    """Extract date from HTML content using various patterns."""
    meta_patterns = [
        r'<meta[^>]+property=["\'](?:og:|article:)published_time["\']\s+content=["\']([^"\']+)["\']',
        r'<meta[^>]+content=["\']([^"\']+)["\']\s+property=["\'](?:og:|article:)published_time["\']',
        r'<meta[^>]+name=["\'](?:published|date|pubdate|publish-date)["\']\s+content=["\']([^"\']+)["\']',
        r'<time[^>]+datetime=["\']([^"\']+)["\']',
        r'"datePublished"\s*:\s*"([^"]+)"',
        r'"dateCreated"\s*:\s*"([^"]+)"',
        r'(?:published|posted|date)[:\s]+(\d{4}-\d{2}-\d{2})',
    ]
    
    for pattern in meta_patterns:
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            date_str = match.group(1)
            date_match = re.search(r'(\d{4})-(\d{2})-(\d{2})', date_str)
            if date_match:
                year, month, day = date_match.groups()
                if 2000 <= int(year) <= 2100:
                    return f"{year}-{month}-{day}T00:00:00Z"
    
    return None


def fetch_date_from_html(url: str) -> tuple:
    """Fetch date from HTML page using requests. Returns (url, date)."""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0',
            'Accept': 'text/html,application/xhtml+xml',
        }
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        
        if response.status_code != 200:
            return (url, None)
        
        date = extract_date_from_html(response.text)
        return (url, date)
        
    except Exception as e:
        logger.debug(f"Error fetching {url}: {e}")
        return (url, None)


def fetch_date_with_selenium(url: str) -> tuple:
    """Fetch date from a JavaScript-rendered page using Selenium. Returns (url, date)."""
    driver = get_selenium_driver()
    if driver is None:
        return (url, None)
    
    try:
        driver.get(url)
        time.sleep(2)  # Wait for JS to render
        html = driver.page_source
        date = extract_date_from_html(html)
        return (url, date)
    except Exception as e:
        logger.debug(f"Selenium error for {url}: {e}")
        return (url, None)
    finally:
        return_selenium_driver(driver)


def fetch_dates_selenium_parallel(urls: list, max_workers: int = 4) -> dict:
    """Fetch dates from multiple URLs using parallel Selenium drivers."""
    if not urls:
        return {}
    
    # Initialize driver pool
    if not init_selenium_pool(num_drivers=min(max_workers, len(urls))):
        logger.warning("Could not initialize Selenium pool, skipping")
        return {}
    
    results = {}
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(fetch_date_with_selenium, url): url for url in urls}
        
        for future in tqdm(as_completed(future_to_url), total=len(urls), desc="Selenium fetching (parallel)"):
            try:
                url, date = future.result()
                results[url] = date
            except Exception as e:
                logger.debug(f"Selenium future error: {e}")
    
    return results


def fetch_dates_parallel(urls: list, max_workers: int = MAX_WORKERS) -> dict:
    """Fetch dates from multiple URLs in parallel. Returns {url: date}."""
    results = {}
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(fetch_date_from_html, url): url for url in urls}
        
        for future in tqdm(as_completed(future_to_url), total=len(urls), desc="HTTP fetching (parallel)"):
            try:
                url, date = future.result()
                results[url] = date
            except Exception as e:
                logger.debug(f"Future error: {e}")
    
    return results


# ============================================================
# ATT&CK TECHNIQUES
# ============================================================

def load_attack_techniques_bulk() -> Dict[str, Dict]:
    """Download and parse the full MITRE ATT&CK enterprise-attack bundle."""
    logger.info("Downloading MITRE ATT&CK enterprise-attack bundle...")
    
    try:
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        response = requests.get(url, timeout=30)
        
        if response.status_code != 200:
            logger.warning(f"Failed to download ATT&CK bundle: HTTP {response.status_code}")
            return {}
        
        data = response.json()
        techniques = {}
        
        if 'objects' in data:
            for obj in data['objects']:
                if obj.get('type') == 'attack-pattern':
                    technique_id = None
                    for ext_ref in obj.get('external_references', []):
                        if ext_ref.get('source_name') == 'mitre-attack':
                            technique_id = ext_ref.get('external_id')
                            break
                    
                    if technique_id:
                        techniques[technique_id] = {
                            'created': obj.get('created'),
                            'modified': obj.get('modified'),
                            'name': obj.get('name', '')
                        }
        
        logger.info(f"Loaded {len(techniques)} ATT&CK techniques")
        return techniques
        
    except Exception as e:
        logger.error(f"Error loading ATT&CK techniques: {e}")
        return {}


# ============================================================
# CVE FETCHING
# ============================================================

def fetch_cve_date(cve_id: str, max_retries: int = 5, api_key: str = None) -> tuple:
    """Fetch CVE publication date from NVD API 2.0. Returns (date, description)."""
    cve_id = cve_id.upper()
    
    if api_key is None:
        api_key = os.environ.get('NVD_API_KEY', NVD_API_KEY)
    
    delay = NVD_API_DELAY_WITH_KEY if api_key else NVD_API_DELAY
    
    for attempt in range(max_retries):
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            headers = {
                'User-Agent': 'SIGMA-Analysis/1.0 (Academic Research Tool)',
                'Accept': 'application/json'
            }
            if api_key:
                headers['apiKey'] = api_key
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                if 'vulnerabilities' in data and len(data['vulnerabilities']) > 0:
                    cve_item = data['vulnerabilities'][0].get('cve', {})
                    published = cve_item.get('published')
                    
                    description = None
                    for desc in cve_item.get('descriptions', []):
                        if desc.get('lang') == 'en':
                            description = desc.get('value', '')
                            break
                    
                    if published:
                        return published, description
                return None, None
                
            elif response.status_code == 403:
                time.sleep(delay * (2 ** attempt))
                continue
            elif response.status_code == 404:
                return None, None
            elif response.status_code == 503:
                time.sleep(5 * (attempt + 1))
                continue
            else:
                time.sleep(delay)
                
        except requests.exceptions.Timeout:
            if attempt < max_retries - 1:
                time.sleep(delay * (attempt + 1))
                continue
        except Exception as e:
            logger.debug(f"Error fetching CVE {cve_id}: {e}")
            if attempt < max_retries - 1:
                time.sleep(delay)
                continue
    
    return None, None


# ============================================================
# DATABASE OPERATIONS
# ============================================================

def create_external_dates_tables(db_path: str):
    """Create tables for storing external dates."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attack_techniques (
            technique_id TEXT PRIMARY KEY,
            created_date TEXT,
            modified_date TEXT,
            name TEXT,
            last_fetched TEXT
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY,
            published_date TEXT,
            description TEXT,
            last_fetched TEXT
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_reports (
            url TEXT PRIMARY KEY,
            domain TEXT,
            source TEXT,
            publication_date TEXT,
            last_fetched TEXT
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS rule_external_refs (
            file_path TEXT,
            commit_hash TEXT,
            ref_type TEXT,
            ref_id TEXT,
            PRIMARY KEY (file_path, commit_hash, ref_type, ref_id)
        )
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_rule_external_refs_file_commit
        ON rule_external_refs(file_path, commit_hash)
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_rule_external_refs_type_id
        ON rule_external_refs(ref_type, ref_id)
    """)
    
    conn.commit()
    conn.close()
    logger.info("Created external dates tables")


def extract_all_external_refs(db_path: str):
    """Extract all external references from rule versions."""
    logger.info("Extracting external references from rule versions...")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT file_path, commit_hash, tags, [references]
        FROM rule_versions
        WHERE tags IS NOT NULL OR [references] IS NOT NULL
    """)
    
    all_attack_techniques = set()
    all_cves = set()
    all_reports = []
    rule_refs = []
    
    rows = cursor.fetchall()
    logger.info(f"Processing {len(rows)} rule versions...")
    
    for file_path, commit_hash, tags_json, refs_json in tqdm(rows, desc="Extracting refs"):
        techniques = extract_attack_techniques(tags_json)
        for tech in techniques:
            all_attack_techniques.add(tech)
            rule_refs.append((file_path, commit_hash, 'attack', tech))
        
        cves = extract_cves(refs_json)
        for cve in cves:
            all_cves.add(cve)
            rule_refs.append((file_path, commit_hash, 'cve', cve))
        
        reports = extract_threat_report_urls(refs_json)
        for report in reports:
            all_reports.append(report)
            rule_refs.append((file_path, commit_hash, 'report', report['url']))
    
    logger.info(f"Found {len(all_attack_techniques)} unique ATT&CK techniques")
    logger.info(f"Found {len(all_cves)} unique CVEs")
    logger.info(f"Found {len(set(r['url'] for r in all_reports))} unique threat report URLs")
    
    cursor.executemany("""
        INSERT OR IGNORE INTO rule_external_refs (file_path, commit_hash, ref_type, ref_id)
        VALUES (?, ?, ?, ?)
    """, rule_refs)
    
    conn.commit()
    conn.close()
    
    return all_attack_techniques, all_cves, all_reports


# ============================================================
# FETCH FUNCTIONS
# ============================================================

def fetch_attack_dates(db_path: str, techniques: Set[str]):
    """Fetch dates for ATT&CK techniques."""
    logger.info(f"Fetching dates for {len(techniques)} ATT&CK techniques...")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT technique_id FROM attack_techniques")
    existing = {row[0] for row in cursor.fetchall()}
    
    to_fetch = techniques - existing
    logger.info(f"Fetching {len(to_fetch)} new techniques (already have {len(existing)})")
    
    if not to_fetch:
        conn.close()
        return
    
    attack_data = load_attack_techniques_bulk()
    
    fetched = 0
    for technique_id in tqdm(to_fetch, desc="Storing ATT&CK dates"):
        tech_data = attack_data.get(technique_id)
        
        if tech_data:
            cursor.execute("""
                INSERT OR REPLACE INTO attack_techniques 
                (technique_id, created_date, modified_date, name, last_fetched)
                VALUES (?, ?, ?, ?, ?)
            """, (technique_id, tech_data.get('created'), tech_data.get('modified'),
                  tech_data.get('name', ''), get_utc_now()))
            fetched += 1
        else:
            cursor.execute("""
                INSERT OR REPLACE INTO attack_techniques (technique_id, last_fetched)
                VALUES (?, ?)
            """, (technique_id, get_utc_now()))
        
        if fetched % 50 == 0:
            conn.commit()
    
    conn.commit()
    conn.close()
    logger.info(f"Fetched dates for {fetched} ATT&CK techniques")


def fetch_cve_dates(db_path: str, cves: Set[str], retry_missing: bool = True):
    """Fetch dates for CVEs from NVD API."""
    logger.info(f"Fetching dates for {len(cves)} CVEs...")
    
    api_key = os.environ.get('NVD_API_KEY')
    if api_key:
        logger.info("Using NVD API key for faster rate limits")
        delay = NVD_API_DELAY_WITH_KEY
    else:
        logger.info("No NVD API key - using default rate limits")
        delay = NVD_API_DELAY
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT cve_id, published_date FROM cves")
    existing_rows = cursor.fetchall()
    existing_with_date = {row[0] for row in existing_rows if row[1]}
    existing_without_date = {row[0] for row in existing_rows if not row[1]}
    
    new_cves = cves - existing_with_date - existing_without_date
    
    if retry_missing:
        to_fetch = new_cves | existing_without_date
        logger.info(f"Fetching {len(new_cves)} new CVEs + retrying {len(existing_without_date)} missing")
    else:
        to_fetch = new_cves
        logger.info(f"Fetching {len(to_fetch)} new CVEs")
    
    if not to_fetch:
        logger.info("No CVEs to fetch")
        conn.close()
        return
    
    fetched = 0
    not_found = 0
    
    for cve_id in tqdm(to_fetch, desc="Fetching CVE dates"):
        published_date, description = fetch_cve_date(cve_id, api_key=api_key)
        
        if published_date:
            cursor.execute("""
                INSERT OR REPLACE INTO cves (cve_id, published_date, description, last_fetched)
                VALUES (?, ?, ?, ?)
            """, (cve_id, published_date, description, get_utc_now()))
            fetched += 1
        else:
            cursor.execute("""
                INSERT OR REPLACE INTO cves (cve_id, last_fetched)
                VALUES (?, ?)
            """, (cve_id, get_utc_now()))
            not_found += 1
        
        if fetched % 10 == 0:
            conn.commit()
        
        time.sleep(delay)
    
    conn.commit()
    conn.close()
    
    logger.info(f"CVE fetch complete: {fetched} fetched, {not_found} not found")


def fetch_report_dates(db_path: str, reports: List[Dict[str, str]], 
                       max_workers: int = MAX_WORKERS, use_selenium: bool = True):
    """Fetch dates for threat reports with parallel processing and Selenium."""
    logger.info(f"Processing {len(reports)} threat report URLs...")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get existing reports
    cursor.execute("SELECT url, publication_date FROM threat_reports")
    existing_rows = cursor.fetchall()
    existing_with_date = {row[0] for row in existing_rows if row[1]}
    existing_without_date = {row[0] for row in existing_rows if not row[1]}
    
    report_map = {r['url']: r for r in reports}
    
    # Insert new reports first (URL-only extraction)
    new_reports = [r for r in reports if r['url'] not in existing_with_date and r['url'] not in existing_without_date]
    
    logger.info(f"Phase 1: URL pattern extraction for {len(new_reports)} new reports...")
    url_extracted = 0
    
    for report in tqdm(new_reports, desc="URL extraction"):
        url = report['url']
        date = extract_date_from_url(url)
        
        cursor.execute("""
            INSERT OR IGNORE INTO threat_reports (url, domain, source, publication_date, last_fetched)
            VALUES (?, ?, ?, ?, ?)
        """, (url, report.get('domain', ''), report.get('source', ''), date, get_utc_now()))
        
        if date:
            url_extracted += 1
    
    conn.commit()
    logger.info(f"Extracted {url_extracted} dates from URLs")
    
    # Get reports still missing dates
    cursor.execute("SELECT url, domain FROM threat_reports WHERE publication_date IS NULL")
    still_missing = cursor.fetchall()
    
    if not still_missing:
        logger.info("All reports have dates!")
        conn.close()
        return
    
    # Phase 2: Parallel HTTP fetching
    high_value_domains = [
        'cisa.gov', 'us-cert.gov', 'mandiant.com', 'crowdstrike.com',
        'talosintelligence.com', 'microsoft.com', 'securelist.com',
        'sentinelone.com', 'proofpoint.com', 'fireeye.com'
    ]
    
    high_value_urls = [url for url, domain in still_missing if any(d in domain for d in high_value_domains)]
    
    if high_value_urls:
        logger.info(f"Phase 2: Parallel HTTP fetching for {len(high_value_urls)} high-value sources...")
        results = fetch_dates_parallel(high_value_urls, max_workers=max_workers)
        
        html_extracted = 0
        for url, date in results.items():
            if date:
                cursor.execute("""
                    UPDATE threat_reports SET publication_date = ?, last_fetched = ? WHERE url = ?
                """, (date, get_utc_now(), url))
                html_extracted += 1
        
        conn.commit()
        logger.info(f"Extracted {html_extracted} dates from HTML")
    
    # Phase 3: Selenium for JS-rendered pages (parallel)
    if use_selenium:
        cursor.execute("SELECT url, domain FROM threat_reports WHERE publication_date IS NULL")
        still_missing_after_http = cursor.fetchall()
        
        js_heavy_domains = ['unit42.paloaltonetworks.com', 'cisa.gov', 'crowdstrike.com']
        js_urls = [url for url, domain in still_missing_after_http 
                   if any(d in domain for d in js_heavy_domains)]
        
        if js_urls:
            # Use up to 4 parallel Selenium drivers (more can cause resource issues)
            selenium_workers = min(4, max_workers)
            logger.info(f"Phase 3: Parallel Selenium for {len(js_urls)} JS-rendered pages ({selenium_workers} drivers)...")
            
            results = fetch_dates_selenium_parallel(js_urls, max_workers=selenium_workers)
            
            selenium_extracted = 0
            for url, date in results.items():
                if date:
                    cursor.execute("""
                        UPDATE threat_reports SET publication_date = ?, last_fetched = ? WHERE url = ?
                    """, (date, get_utc_now(), url))
                    selenium_extracted += 1
            
            conn.commit()
            logger.info(f"Extracted {selenium_extracted} dates via Selenium")
            close_selenium_drivers()
    
    # Final stats
    cursor.execute("SELECT COUNT(*) FROM threat_reports")
    total = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM threat_reports WHERE publication_date IS NOT NULL")
    with_date = cursor.fetchone()[0]
    
    logger.info(f"Report fetch complete: {with_date}/{total} ({100*with_date/total:.1f}%) with dates")
    
    # Show breakdown
    logger.info("\nBreakdown by domain:")
    cursor.execute('''
        SELECT domain, COUNT(*) as total,
               SUM(CASE WHEN publication_date IS NOT NULL THEN 1 ELSE 0 END) as with_date
        FROM threat_reports GROUP BY domain ORDER BY total DESC LIMIT 10
    ''')
    for domain, total, wd in cursor.fetchall():
        pct = 100*wd/total if total > 0 else 0
        status = "[OK]" if pct >= 80 else "[--]" if pct >= 50 else "[XX]"
        logger.info(f"  {status} {domain}: {wd}/{total} ({pct:.0f}%)")
    
    conn.close()


# ============================================================
# MAIN
# ============================================================

def fetch_external_dates(db_path: str, max_workers: int = MAX_WORKERS, use_selenium: bool = True):
    """Main function to extract and fetch all external dates."""
    logger.info("=" * 60)
    logger.info("Phase 6: Fetching external dates for responsiveness analysis")
    logger.info(f"Workers: {max_workers}, Selenium: {use_selenium}")
    logger.info("=" * 60)
    
    create_external_dates_tables(db_path)
    techniques, cves, reports = extract_all_external_refs(db_path)
    
    if techniques:
        fetch_attack_dates(db_path, techniques)
    
    if cves:
        fetch_cve_dates(db_path, cves)
    
    if reports:
        fetch_report_dates(db_path, reports, max_workers=max_workers, use_selenium=use_selenium)
    
    logger.info("=" * 60)
    logger.info("Phase 6 Complete!")
    logger.info("=" * 60)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Phase 6: Fetch external dates")
    parser.add_argument("--db-path", type=str, default="data/sigma_analysis.db")
    parser.add_argument("--workers", type=int, default=MAX_WORKERS, help="Parallel HTTP workers")
    parser.add_argument("--no-selenium", action="store_true", help="Disable Selenium")
    
    args = parser.parse_args()
    
    try:
        fetch_external_dates(args.db_path, max_workers=args.workers, use_selenium=not args.no_selenium)
    finally:
        close_selenium_drivers()
