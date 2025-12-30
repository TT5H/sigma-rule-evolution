"""
Phase 6: Fetch external dates for responsiveness analysis
Goal: Extract and fetch dates for:
- MITRE ATT&CK technique release/update dates
- CVE publication dates (NVD)
- Threat report publication dates (CISA, Mandiant, etc.)
"""
import sqlite3
import json
import re
import requests
import time
from pathlib import Path
from datetime import datetime
from tqdm import tqdm
import logging
import sys
from urllib.parse import urlparse
from typing import List, Dict, Optional, Set

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

# Rate limiting
NVD_API_DELAY = 0.7  # NVD API allows 50 requests per 30 seconds - be conservative
NVD_API_DELAY_WITH_KEY = 0.15  # With API key: 50 requests per second
ATTACK_API_DELAY = 0.1  # MITRE ATT&CK API is more lenient

# NVD API Key (optional, set via environment variable for faster fetching)
NVD_API_KEY = None  # Will be loaded from environment if available


def extract_attack_techniques(tags_json: str) -> Set[str]:
    """
    Extract ATT&CK technique IDs from tags JSON.
    Patterns: attack.t####, attack.####, attack-t####
    """
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
            
            # Pattern: attack.t#### or attack.####
            match = re.search(r'attack\.t?(\d{4,5})', tag, re.IGNORECASE)
            if match:
                technique_id = f"T{match.group(1)}"
                techniques.add(technique_id)
            
            # Pattern: attack-t####
            match = re.search(r'attack-t(\d{4,5})', tag, re.IGNORECASE)
            if match:
                technique_id = f"T{match.group(1)}"
                techniques.add(technique_id)
        
        return techniques
    except Exception as e:
        logger.debug(f"Error parsing tags: {e}")
        return set()


def extract_cves(references_json: str) -> Set[str]:
    """
    Extract CVE IDs from references JSON.
    Pattern: CVE-YYYY-NNNNN
    """
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
            
            # Pattern: CVE-YYYY-NNNNN
            matches = re.findall(r'CVE-\d{4}-\d{4,}', ref, re.IGNORECASE)
            cves.update(matches)
        
        return cves
    except Exception as e:
        logger.debug(f"Error parsing references: {e}")
        return set()


def extract_threat_report_urls(references_json: str) -> List[Dict[str, str]]:
    """
    Extract threat report URLs from references.
    Identifies URLs from known sources: CISA, Mandiant, FireEye, etc.
    """
    if not references_json:
        return []
    
    try:
        references = json.loads(references_json) if isinstance(references_json, str) else references_json
        if not isinstance(references, list):
            return []
        
        report_urls = []
        known_domains = [
            'cisa.gov',
            'us-cert.gov',
            'mandiant.com',
            'fireeye.com',
            'crowdstrike.com',
            'microsoft.com/security',
            'securelist.com',
            'talosintelligence.com',
            'unit42.paloaltonetworks.com',
            'blog.talosintelligence.com',
            'symantec.com/blogs',
            'trendmicro.com',
            'proofpoint.com',
            'sentinelone.com',
            'recordedfuture.com',
            'dragos.com',
            'dragos.com/resource',
        ]
        
        for ref in references:
            if not isinstance(ref, str):
                continue
            
            # Check if it's a URL
            if not (ref.startswith('http://') or ref.startswith('https://')):
                continue
            
            try:
                parsed = urlparse(ref)
                domain = parsed.netloc.lower()
                
                # Check if domain matches known threat intelligence sources
                for known_domain in known_domains:
                    if known_domain in domain:
                        report_urls.append({
                            'url': ref,
                            'domain': domain,
                            'source': known_domain.split('.')[0]  # Extract main domain name
                        })
                        break
            except Exception:
                continue
        
        return report_urls
    except Exception as e:
        logger.debug(f"Error parsing references: {e}")
        return []




def load_attack_techniques_bulk() -> Dict[str, Dict]:
    """
    Download and parse the full MITRE ATT&CK enterprise-attack bundle.
    Returns a dict mapping technique_id -> {created, modified, name}
    """
    logger.info("Downloading MITRE ATT&CK enterprise-attack bundle...")
    
    try:
        # Download the full enterprise-attack STIX bundle
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        response = requests.get(url, timeout=30)
        
        if response.status_code != 200:
            logger.warning(f"Failed to download ATT&CK bundle: HTTP {response.status_code}")
            return {}
        
        data = response.json()
        techniques = {}
        
        # Parse STIX objects
        if 'objects' in data:
            for obj in data['objects']:
                obj_type = obj.get('type')
                if obj_type == 'attack-pattern':
                    # Extract technique ID from external_references
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


def fetch_cve_date(cve_id: str, max_retries: int = 5, api_key: str = None) -> tuple:
    """
    Fetch CVE publication date and description from NVD API 2.0 with enhanced retry logic.
    
    Args:
        cve_id: CVE identifier (e.g., CVE-2021-44228)
        max_retries: Maximum number of retry attempts
        api_key: Optional NVD API key for faster rate limits
    
    Returns:
        Tuple of (published_date, description) or (None, None) if not found
    """
    import os
    
    # Try to get API key from environment if not provided
    if api_key is None:
        api_key = os.environ.get('NVD_API_KEY', NVD_API_KEY)
    
    # Determine delay based on whether we have an API key
    delay = NVD_API_DELAY_WITH_KEY if api_key else NVD_API_DELAY
    
    for attempt in range(max_retries):
        try:
            # NVD API v2.0 endpoint
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            
            headers = {
                'User-Agent': 'SIGMA-Analysis/1.0 (Academic Research Tool)',
                'Accept': 'application/json'
            }
            
            # Add API key if available
            if api_key:
                headers['apiKey'] = api_key
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                if 'vulnerabilities' in data and len(data['vulnerabilities']) > 0:
                    vuln = data['vulnerabilities'][0]
                    cve_item = vuln.get('cve', {})
                    published = cve_item.get('published')
                    
                    # Extract description (English preferred)
                    description = None
                    descriptions = cve_item.get('descriptions', [])
                    for desc in descriptions:
                        if desc.get('lang') == 'en':
                            description = desc.get('value', '')
                            break
                    if not description and descriptions:
                        description = descriptions[0].get('value', '')
                    
                    if published:
                        return published, description
                    
                # CVE found but no published date
                return None, None
                
            elif response.status_code == 403:
                # Rate limit - exponential backoff
                wait_time = delay * (2 ** attempt)
                logger.debug(f"Rate limited for {cve_id}, waiting {wait_time:.1f}s (attempt {attempt + 1}/{max_retries})")
                time.sleep(wait_time)
                continue
                
            elif response.status_code == 404:
                # CVE not found in NVD
                logger.debug(f"CVE {cve_id} not found in NVD")
                return None, None
                
            elif response.status_code == 503:
                # Service unavailable - longer wait
                wait_time = 5 * (attempt + 1)
                logger.debug(f"NVD service unavailable for {cve_id}, waiting {wait_time}s")
                time.sleep(wait_time)
                continue
            
            else:
                logger.debug(f"Unexpected status {response.status_code} for {cve_id}")
                time.sleep(delay)
            
        except requests.exceptions.Timeout:
            wait_time = delay * (attempt + 1)
            logger.debug(f"Timeout fetching {cve_id}, attempt {attempt + 1}/{max_retries}, waiting {wait_time:.1f}s")
            if attempt < max_retries - 1:
                time.sleep(wait_time)
                continue
                
        except requests.exceptions.ConnectionError as e:
            wait_time = 2 * (attempt + 1)
            logger.debug(f"Connection error for {cve_id}: {e}, waiting {wait_time}s")
            if attempt < max_retries - 1:
                time.sleep(wait_time)
                continue
                
        except requests.exceptions.RequestException as e:
            logger.debug(f"Request error fetching {cve_id}: {e}")
            if attempt < max_retries - 1:
                time.sleep(delay * (attempt + 1))
                continue
                
        except json.JSONDecodeError as e:
            logger.debug(f"JSON decode error for {cve_id}: {e}")
            if attempt < max_retries - 1:
                time.sleep(delay)
                continue
                
        except Exception as e:
            logger.debug(f"Unexpected error fetching CVE {cve_id}: {e}")
            if attempt < max_retries - 1:
                time.sleep(delay)
                continue
    
    return None, None


def fetch_report_date(url: str) -> Optional[str]:
    """
    Attempt to fetch publication date from threat report URL.
    Uses multiple strategies:
    1. Extract date from URL pattern
    2. Try to fetch from page HTML metadata (og:published_time, article:published_time, etc.)
    3. Try to extract from page content
    """
    try:
        # Strategy 1: Try to extract date from URL pattern (common in threat reports)
        # Pattern: /YYYY/MM/DD/ or /YYYY-MM-DD/ or /YYYY/MM/ or YYYY/MM/DD
        date_patterns = [
            r'/(\d{4})/(\d{2})/(\d{2})[/-]',  # /2024/01/15/ or /2024/01/15-
            r'/(\d{4})-(\d{2})-(\d{2})[/-]',  # /2024-01-15/ or /2024-01-15-
            r'/(\d{4})/(\d{2})[/-]',  # /2024/01/ or /2024/01-
            r'(\d{4})/(\d{2})/(\d{2})',  # 2024/01/15 (no leading slash)
            r'(\d{4})-(\d{2})-(\d{2})',  # 2024-01-15 (no leading slash)
        ]
        
        for pattern in date_patterns:
            match = re.search(pattern, url)
            if match:
                groups = match.groups()
                if len(groups) == 3:
                    year, month, day = groups
                    # Validate date components
                    if 2000 <= int(year) <= 2100 and 1 <= int(month) <= 12 and 1 <= int(day) <= 31:
                        return f"{year}-{month}-{day}T00:00:00Z"
                elif len(groups) == 2:
                    year, month = groups
                    if 2000 <= int(year) <= 2100 and 1 <= int(month) <= 12:
                        return f"{year}-{month}-01T00:00:00Z"
        
        # Strategy 2: Try to fetch from page HTML metadata
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (Research Tool)'
            }
            response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
            
            if response.status_code == 200:
                html_content = response.text
                
                # Look for common meta tags with publication dates
                meta_patterns = [
                    r'<meta\s+property=["\']og:published_time["\']\s+content=["\']([^"\']+)["\']',
                    r'<meta\s+property=["\']article:published_time["\']\s+content=["\']([^"\']+)["\']',
                    r'<meta\s+name=["\']published["\']\s+content=["\']([^"\']+)["\']',
                    r'<meta\s+name=["\']date["\']\s+content=["\']([^"\']+)["\']',
                    r'<time[^>]*datetime=["\']([^"\']+)["\']',
                    r'<time[^>]*pubdate[^>]*>([^<]+)</time>',
                ]
                
                for pattern in meta_patterns:
                    match = re.search(pattern, html_content, re.IGNORECASE)
                    if match:
                        date_str = match.group(1)
                        # Try to parse and normalize the date
                        try:
                            # Common formats: 2024-01-15, 2024-01-15T10:30:00Z, etc.
                            date_match = re.search(r'(\d{4})-(\d{2})-(\d{2})', date_str)
                            if date_match:
                                year, month, day = date_match.groups()
                                if 2000 <= int(year) <= 2100:
                                    return f"{year}-{month}-{day}T00:00:00Z"
                        except:
                            pass
                
                # Strategy 3: Look for date patterns in page content (last resort)
                # Look for patterns like "Published: 2024-01-15" or "Date: January 15, 2024"
                content_date_patterns = [
                    r'(?:published|date|posted)[:\s]+(\d{4})-(\d{2})-(\d{2})',
                    r'(\d{4})-(\d{2})-(\d{2})\s+(?:published|posted|released)',
                ]
                
                for pattern in content_date_patterns:
                    match = re.search(pattern, html_content, re.IGNORECASE)
                    if match:
                        groups = match.groups()
                        if len(groups) == 3:
                            year, month, day = groups
                            if 2000 <= int(year) <= 2100:
                                return f"{year}-{month}-{day}T00:00:00Z"
        
        except requests.exceptions.RequestException:
            # If we can't fetch the page, that's okay - we tried
            pass
        except Exception as e:
            logger.debug(f"Error fetching page for {url}: {e}")
        
        return None
        
    except Exception as e:
        logger.debug(f"Error extracting date from URL {url}: {e}")
        return None


def create_external_dates_tables(db_path: str):
    """
    Create tables for storing external dates.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Table for ATT&CK techniques
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attack_techniques (
            technique_id TEXT PRIMARY KEY,
            created_date TEXT,
            modified_date TEXT,
            name TEXT,
            last_fetched TEXT
        )
    """)
    
    # Table for CVEs
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY,
            published_date TEXT,
            description TEXT,
            last_fetched TEXT
        )
    """)
    
    # Table for threat reports
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_reports (
            url TEXT PRIMARY KEY,
            domain TEXT,
            source TEXT,
            publication_date TEXT,
            last_fetched TEXT
        )
    """)
    
    # Table linking rule versions to external references
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS rule_external_refs (
            file_path TEXT,
            commit_hash TEXT,
            ref_type TEXT,  -- 'attack', 'cve', 'report'
            ref_id TEXT,    -- technique_id, cve_id, or url
            PRIMARY KEY (file_path, commit_hash, ref_type, ref_id),
            FOREIGN KEY (file_path, commit_hash) REFERENCES rule_versions(file_path, commit_hash)
        )
    """)
    
    # Create indexes
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
    """
    Extract all external references from rule versions.
    """
    logger.info("Extracting external references from rule versions...")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get all rule versions with tags and references
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
        # Extract ATT&CK techniques
        techniques = extract_attack_techniques(tags_json)
        for tech in techniques:
            all_attack_techniques.add(tech)
            rule_refs.append((file_path, commit_hash, 'attack', tech))
        
        # Extract CVEs
        cves = extract_cves(refs_json)
        for cve in cves:
            all_cves.add(cve)
            rule_refs.append((file_path, commit_hash, 'cve', cve))
        
        # Extract threat reports
        reports = extract_threat_report_urls(refs_json)
        for report in reports:
            all_reports.append(report)
            rule_refs.append((file_path, commit_hash, 'report', report['url']))
    
    logger.info(f"Found {len(all_attack_techniques)} unique ATT&CK techniques")
    logger.info(f"Found {len(all_cves)} unique CVEs")
    logger.info(f"Found {len(all_reports)} unique threat report URLs")
    
    # Store rule-external reference mappings
    cursor.executemany("""
        INSERT OR IGNORE INTO rule_external_refs (file_path, commit_hash, ref_type, ref_id)
        VALUES (?, ?, ?, ?)
    """, rule_refs)
    
    conn.commit()
    conn.close()
    
    return all_attack_techniques, all_cves, all_reports


def fetch_attack_dates(db_path: str, techniques: Set[str]):
    """
    Fetch dates for ATT&CK techniques using bulk download.
    """
    logger.info(f"Fetching dates for {len(techniques)} ATT&CK techniques...")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check which techniques we already have
    cursor.execute("SELECT technique_id FROM attack_techniques")
    existing = {row[0] for row in cursor.fetchall()}
    
    to_fetch = techniques - existing
    logger.info(f"Fetching {len(to_fetch)} new techniques (already have {len(existing)})")
    
    if not to_fetch:
        conn.close()
        return
    
    # Download full ATT&CK bundle
    attack_data = load_attack_techniques_bulk()
    
    fetched = 0
    for technique_id in tqdm(to_fetch, desc="Storing ATT&CK dates"):
        tech_data = attack_data.get(technique_id)
        
        if tech_data:
            cursor.execute("""
                INSERT OR REPLACE INTO attack_techniques 
                (technique_id, created_date, modified_date, name, last_fetched)
                VALUES (?, ?, ?, ?, ?)
            """, (
                technique_id,
                tech_data.get('created'),
                tech_data.get('modified'),
                tech_data.get('name', ''),
                datetime.utcnow().isoformat() + 'Z'
            ))
            fetched += 1
        else:
            # Store even if we couldn't find it (for tracking)
            cursor.execute("""
                INSERT OR REPLACE INTO attack_techniques 
                (technique_id, last_fetched)
                VALUES (?, ?)
            """, (technique_id, datetime.utcnow().isoformat() + 'Z'))
        
        if fetched % 50 == 0:
            conn.commit()
    
    conn.commit()
    conn.close()
    logger.info(f"Fetched dates for {fetched} ATT&CK techniques")


def fetch_cve_dates(db_path: str, cves: Set[str], retry_missing: bool = True):
    """
    Fetch dates for CVEs from NVD API 2.0 with improved retry logic.
    
    Args:
        db_path: Path to SQLite database
        cves: Set of CVE IDs to fetch
        retry_missing: If True, retry CVEs that previously had no published date
    """
    import os
    
    logger.info(f"Fetching dates for {len(cves)} CVEs...")
    
    # Check for API key
    api_key = os.environ.get('NVD_API_KEY')
    if api_key:
        logger.info("Using NVD API key for faster rate limits")
        delay = NVD_API_DELAY_WITH_KEY
    else:
        logger.info("No NVD API key found - using default rate limits (set NVD_API_KEY env var for faster fetching)")
        delay = NVD_API_DELAY
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check which CVEs we already have with dates
    cursor.execute("SELECT cve_id, published_date FROM cves")
    existing_rows = cursor.fetchall()
    existing_with_date = {row[0] for row in existing_rows if row[1]}
    existing_without_date = {row[0] for row in existing_rows if not row[1]}
    
    # Determine what to fetch
    new_cves = cves - existing_with_date - existing_without_date
    
    if retry_missing:
        # Also retry CVEs that we tried before but didn't get a date
        to_fetch = new_cves | existing_without_date
        logger.info(f"Fetching {len(new_cves)} new CVEs + retrying {len(existing_without_date)} missing")
    else:
        to_fetch = new_cves
        logger.info(f"Fetching {len(to_fetch)} new CVEs (already have {len(existing_with_date)} with dates)")
    
    if not to_fetch:
        logger.info("No CVEs to fetch")
        conn.close()
        return
    
    fetched = 0
    not_found = 0
    errors = 0
    consecutive_errors = 0
    
    for cve_id in tqdm(to_fetch, desc="Fetching CVE dates"):
        try:
            published_date, description = fetch_cve_date(cve_id, api_key=api_key)
            
            if published_date:
                cursor.execute("""
                    INSERT OR REPLACE INTO cves 
                    (cve_id, published_date, description, last_fetched)
                    VALUES (?, ?, ?, ?)
                """, (cve_id, published_date, description, datetime.utcnow().isoformat() + 'Z'))
                fetched += 1
                consecutive_errors = 0  # Reset error counter on success
            else:
                # Store even if we couldn't fetch (for tracking)
                cursor.execute("""
                    INSERT OR REPLACE INTO cves 
                    (cve_id, last_fetched)
                    VALUES (?, ?)
                """, (cve_id, datetime.utcnow().isoformat() + 'Z'))
                not_found += 1
            
            # Commit every 10 successful fetches
            if fetched % 10 == 0:
                conn.commit()
            
            # Rate limiting - always sleep between requests
            time.sleep(delay)
            
        except Exception as e:
            logger.debug(f"Error fetching {cve_id}: {e}")
            errors += 1
            consecutive_errors += 1
            
            # If we have many consecutive errors, back off
            if consecutive_errors >= 5:
                logger.warning(f"Multiple consecutive errors, pausing for 30 seconds...")
                time.sleep(30)
                consecutive_errors = 0
            elif consecutive_errors >= 3:
                logger.warning(f"Consecutive errors, pausing for 10 seconds...")
                time.sleep(10)
    
    conn.commit()
    conn.close()
    
    logger.info(f"CVE fetch complete:")
    logger.info(f"  - Successfully fetched: {fetched}")
    logger.info(f"  - Not found/failed: {not_found}")
    logger.info(f"  - Errors: {errors}")


def fetch_report_dates(db_path: str, reports: List[Dict[str, str]]):
    """
    Fetch dates for threat reports.
    """
    logger.info(f"Processing {len(reports)} threat report URLs...")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check which reports we already have
    cursor.execute("SELECT url FROM threat_reports")
    existing = {row[0] for row in cursor.fetchall()}
    
    to_fetch = [r for r in reports if r['url'] not in existing]
    logger.info(f"Processing {len(to_fetch)} new reports (already have {len(existing)})")
    
    fetched = 0
    for report in tqdm(to_fetch, desc="Processing report URLs"):
        date = fetch_report_date(report['url'])
        
        cursor.execute("""
            INSERT OR REPLACE INTO threat_reports 
            (url, domain, source, publication_date, last_fetched)
            VALUES (?, ?, ?, ?, ?)
        """, (
            report['url'],
            report['domain'],
            report['source'],
            date,
            datetime.utcnow().isoformat() + 'Z'
        ))
        
        if date:
            fetched += 1
        
        # Commit every 50 reports or every 100 attempts
        if fetched % 50 == 0 or (fetched + len(to_fetch) - fetched) % 100 == 0:
            conn.commit()
        
        # Small delay to be respectful
        time.sleep(0.2)
    
    conn.commit()
    conn.close()
    logger.info(f"Extracted dates for {fetched} threat reports")


def fetch_external_dates(db_path: str):
    """
    Main function to extract and fetch all external dates.
    """
    logger.info("=" * 60)
    logger.info("Phase 6: Fetching external dates for responsiveness analysis")
    logger.info("=" * 60)
    
    # Create tables
    create_external_dates_tables(db_path)
    
    # Extract all external references
    techniques, cves, reports = extract_all_external_refs(db_path)
    
    # Fetch dates (with rate limiting)
    if techniques:
        fetch_attack_dates(db_path, techniques)
    
    if cves:
        fetch_cve_dates(db_path, cves)
    
    if reports:
        fetch_report_dates(db_path, reports)
    
    logger.info("=" * 60)
    logger.info("Phase 6 Complete!")
    logger.info("=" * 60)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Phase 6: Fetch external dates")
    parser.add_argument("--db-path", type=str, default="data/sigma_analysis.db",
                       help="Path to SQLite database")
    
    args = parser.parse_args()
    
    fetch_external_dates(args.db_path)

