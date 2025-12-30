"""
Phase 4: Compute diffs between versions and classify changes
Goal: Compare consecutive versions and label change type
"""
import sqlite3
import json
import logging
from pathlib import Path
import pandas as pd
from tqdm import tqdm
from difflib import unified_diff
import sys

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('phase4_compute_diffs.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


def safe_json_parse(json_str, field_name, default=None):
    """
    Safely parse JSON string with logging.
    
    Args:
        json_str: JSON string to parse
        field_name: Name of field for logging
        default: Default value if parsing fails
    
    Returns:
        Parsed object or default
    """
    if json_str is None:
        return default
    
    if isinstance(json_str, (dict, list)):
        return json_str  # Already parsed
    
    if not isinstance(json_str, str):
        logger.warning(f"Field {field_name} is not a string or dict/list: {type(json_str)}")
        return default
    
    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse JSON for {field_name}: {e}. Value: {json_str[:100] if len(str(json_str)) > 100 else json_str}")
        return default
    except Exception as e:
        logger.warning(f"Unexpected error parsing {field_name}: {e}")
        return default


def compute_diff(old_version, new_version, file_path="", old_commit="", new_commit=""):
    """
    Compute diff between two rule versions.
    
    Args:
        old_version: Dict with old version data
        new_version: Dict with new version data
        file_path: File path for logging
        old_commit: Old commit hash for logging
        new_commit: New commit hash for logging
    
    Returns:
        dict with change classification and metrics
    """
    try:
        result = {
            'detection_changed': 0,
            'logsource_changed': 0,
            'tags_changed': 0,
            'references_changed': 0,
            'falsepositives_changed': 0,
            'metadata_changed': 0,
            'lines_added': 0,
            'lines_deleted': 0
        }
        
        # Parse JSON fields safely
        old_detection = safe_json_parse(old_version.get('detection'), 'old_detection', {})
        new_detection = safe_json_parse(new_version.get('detection'), 'new_detection', {})
        
        old_tags = safe_json_parse(old_version.get('tags'), 'old_tags', [])
        new_tags = safe_json_parse(new_version.get('tags'), 'new_tags', [])
        
        # Handle [references] column name
        old_refs = safe_json_parse(old_version.get('[references]') or old_version.get('references'), 'old_references', [])
        new_refs = safe_json_parse(new_version.get('[references]') or new_version.get('references'), 'new_references', [])
        
        old_fp = safe_json_parse(old_version.get('falsepositives'), 'old_falsepositives', [])
        new_fp = safe_json_parse(new_version.get('falsepositives'), 'new_falsepositives', [])
        
        # Compare structured fields
        try:
            if old_detection != new_detection:
                result['detection_changed'] = 1
        except Exception as e:
            logger.warning(f"Error comparing detection for {file_path} ({old_commit} -> {new_commit}): {e}")
        
        try:
            old_logsource = (old_version.get('logsource_product'), 
                             old_version.get('logsource_category'),
                             old_version.get('logsource_service'))
            new_logsource = (new_version.get('logsource_product'),
                             new_version.get('logsource_category'),
                             new_version.get('logsource_service'))
            if old_logsource != new_logsource:
                result['logsource_changed'] = 1
        except Exception as e:
            logger.warning(f"Error comparing logsource for {file_path} ({old_commit} -> {new_commit}): {e}")
        
        try:
            if old_tags != new_tags:
                result['tags_changed'] = 1
        except Exception as e:
            logger.warning(f"Error comparing tags for {file_path} ({old_commit} -> {new_commit}): {e}")
        
        try:
            if old_refs != new_refs:
                result['references_changed'] = 1
        except Exception as e:
            logger.warning(f"Error comparing references for {file_path} ({old_commit} -> {new_commit}): {e}")
        
        try:
            if old_fp != new_fp:
                result['falsepositives_changed'] = 1
        except Exception as e:
            logger.warning(f"Error comparing falsepositives for {file_path} ({old_commit} -> {new_commit}): {e}")
        
        # Metadata changes (title, status, level, rule_id)
        try:
            old_metadata = (old_version.get('title'), old_version.get('status'),
                            old_version.get('level'), old_version.get('rule_id'))
            new_metadata = (new_version.get('title'), new_version.get('status'),
                            new_version.get('level'), new_version.get('rule_id'))
            if old_metadata != new_metadata:
                result['metadata_changed'] = 1
        except Exception as e:
            logger.warning(f"Error comparing metadata for {file_path} ({old_commit} -> {new_commit}): {e}")
        
        # Compute line-level diff
        try:
            old_text = old_version.get('yaml_text', '')
            new_text = new_version.get('yaml_text', '')
            
            if old_text is None:
                old_text = ''
            if new_text is None:
                new_text = ''
            
            old_lines = old_text.splitlines() if isinstance(old_text, str) else []
            new_lines = new_text.splitlines() if isinstance(new_text, str) else []
            
            diff = list(unified_diff(old_lines, new_lines, lineterm=''))
            
            lines_added = sum(1 for line in diff if line.startswith('+') and not line.startswith('+++'))
            lines_deleted = sum(1 for line in diff if line.startswith('-') and not line.startswith('---'))
            
            result['lines_added'] = lines_added
            result['lines_deleted'] = lines_deleted
        except Exception as e:
            logger.warning(f"Error computing line diff for {file_path} ({old_commit} -> {new_commit}): {e}")
            result['lines_added'] = 0
            result['lines_deleted'] = 0
        
        return result
    
    except Exception as e:
        logger.error(f"Critical error in compute_diff for {file_path} ({old_commit} -> {new_commit}): {e}", exc_info=True)
        # Return default result on critical error
        return {
            'detection_changed': 0,
            'logsource_changed': 0,
            'tags_changed': 0,
            'references_changed': 0,
            'falsepositives_changed': 0,
            'metadata_changed': 0,
            'lines_added': 0,
            'lines_deleted': 0
        }


def compute_all_diffs(db_path):
    """
    Compute diffs for all consecutive rule versions.
    
    Args:
        db_path: Path to SQLite database
    """
    logger.info("=" * 60)
    logger.info("Phase 4: Computing diffs between versions...")
    logger.info("=" * 60)
    
    try:
        conn = sqlite3.connect(db_path, timeout=60.0)
        # Optimize for bulk operations
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=10000")
        cursor = conn.cursor()
        
        logger.info("Creating version_diffs table...")
        
        # Create version_diffs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS version_diffs (
                file_path TEXT,
                old_commit TEXT,
                new_commit TEXT,
                date TEXT,
                detection_changed INTEGER,
                logsource_changed INTEGER,
                tags_changed INTEGER,
                references_changed INTEGER,
                falsepositives_changed INTEGER,
                metadata_changed INTEGER,
                lines_added INTEGER,
                lines_deleted INTEGER,
                PRIMARY KEY (file_path, old_commit, new_commit)
            )
        """)
        
        # Create index for faster lookups
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_version_diffs_file 
            ON version_diffs(file_path, old_commit, new_commit)
        """)
        
        conn.commit()
        logger.info("Table created successfully")
        
        # Get all rule versions ordered by file and date
        logger.info("Loading rule versions from database...")
        df = pd.read_sql("""
            SELECT file_path, commit_hash, date,
                   rule_id, title, status, level,
                   logsource_product, logsource_category, logsource_service,
                   tags, [references], falsepositives, detection, yaml_text
            FROM rule_versions
            WHERE yaml_text IS NOT NULL
            ORDER BY file_path, date
        """, conn)
        
        logger.info(f"Loaded {len(df)} rule versions from database")
        
        if len(df) == 0:
            logger.warning("No rule versions found in database. Make sure Phase 2 and Phase 3 completed successfully.")
            conn.close()
            return
        
        # Count potential diffs
        total_potential_diffs = 0
        for file_path, group in df.groupby('file_path'):
            total_potential_diffs += max(0, len(group) - 1)
        
        logger.info(f"Potential diffs to compute: {total_potential_diffs}")
        
        # Batch check existing diffs for efficiency
        logger.info("Checking for existing diffs...")
        existing_diffs_df = pd.read_sql("""
            SELECT file_path, old_commit, new_commit 
            FROM version_diffs
        """, conn)
        
        if len(existing_diffs_df) > 0:
            existing_diffs_set = set(
                (row['file_path'], row['old_commit'], row['new_commit'])
                for _, row in existing_diffs_df.iterrows()
            )
            logger.info(f"Found {len(existing_diffs_set)} existing diffs in database")
        else:
            existing_diffs_set = set()
            logger.info("No existing diffs found")
        
        diffs_computed = 0
        errors = 0
        skipped = 0
        
        # Prepare batch inserts
        batch_inserts = []
        batch_size = 100
        
        # Group by file_path and compute diffs between consecutive versions
        logger.info("Computing diffs...")
        for file_path, group in tqdm(df.groupby('file_path'), desc="Computing diffs", total=df['file_path'].nunique()):
            try:
                versions = group.sort_values('date').reset_index(drop=True)
                
                if len(versions) < 2:
                    logger.debug(f"Skipping {file_path}: only {len(versions)} version(s)")
                    continue
                
                for i in range(1, len(versions)):
                    try:
                        old_version = versions.iloc[i-1].to_dict()
                        new_version = versions.iloc[i].to_dict()
                        
                        old_commit = old_version['commit_hash']
                        new_commit = new_version['commit_hash']
                        date = new_version['date']
                        
                        # Check if diff already exists
                        if (file_path, old_commit, new_commit) in existing_diffs_set:
                            skipped += 1
                            continue
                        
                        # Compute diff with logging context
                        diff_result = compute_diff(
                            old_version, 
                            new_version,
                            file_path=file_path,
                            old_commit=old_commit,
                            new_commit=new_commit
                        )
                        
                        # Add to batch
                        batch_inserts.append((
                            file_path, old_commit, new_commit, date,
                            diff_result['detection_changed'],
                            diff_result['logsource_changed'],
                            diff_result['tags_changed'],
                            diff_result['references_changed'],
                            diff_result['falsepositives_changed'],
                            diff_result['metadata_changed'],
                            diff_result['lines_added'],
                            diff_result['lines_deleted']
                        ))
                        
                        diffs_computed += 1
                        
                        # Execute batch inserts periodically
                        if len(batch_inserts) >= batch_size:
                            try:
                                cursor.executemany("""
                                    INSERT OR REPLACE INTO version_diffs
                                    (file_path, old_commit, new_commit, date,
                                     detection_changed, logsource_changed, tags_changed,
                                     references_changed, falsepositives_changed, metadata_changed,
                                     lines_added, lines_deleted)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                """, batch_inserts)
                                conn.commit()
                                logger.debug(f"Committed batch of {len(batch_inserts)} diffs")
                                batch_inserts = []
                            except Exception as e:
                                logger.error(f"Error inserting batch: {e}", exc_info=True)
                                errors += len(batch_inserts)
                                batch_inserts = []
                    
                    except Exception as e:
                        logger.error(f"Error processing diff for {file_path} (version {i-1} -> {i}): {e}", exc_info=True)
                        errors += 1
                        continue
            
            except Exception as e:
                logger.error(f"Error processing file {file_path}: {e}", exc_info=True)
                errors += 1
                continue
        
        # Insert remaining batch
        if batch_inserts:
            try:
                cursor.executemany("""
                    INSERT OR REPLACE INTO version_diffs
                    (file_path, old_commit, new_commit, date,
                     detection_changed, logsource_changed, tags_changed,
                     references_changed, falsepositives_changed, metadata_changed,
                     lines_added, lines_deleted)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, batch_inserts)
                conn.commit()
                logger.info(f"Committed final batch of {len(batch_inserts)} diffs")
            except Exception as e:
                logger.error(f"Error inserting final batch: {e}", exc_info=True)
                errors += len(batch_inserts)
        
        conn.commit()
        conn.close()
        
        logger.info("=" * 60)
        logger.info("Phase 4 Complete:")
        logger.info(f"  - Computed {diffs_computed} diffs")
        logger.info(f"  - Skipped {skipped} existing diffs")
        logger.info(f"  - Errors: {errors}")
        logger.info("=" * 60)
        
        print(f"\nPhase 4 Complete:")
        print(f"  - Computed {diffs_computed} diffs")
        print(f"  - Skipped {skipped} existing diffs")
        print(f"  - Errors: {errors}")
        if errors > 0:
            print(f"  - Check phase4_compute_diffs.log for details")
    
    except Exception as e:
        logger.error(f"Critical error in compute_all_diffs: {e}", exc_info=True)
        print(f"\nError in Phase 4: {e}")
        print("Check phase4_compute_diffs.log for details")
        raise


if __name__ == "__main__":
    import sys
    db_path = Path(sys.argv[2]) if len(sys.argv) > 1 else Path("../data/sigma_analysis.db")
    
    compute_all_diffs(db_path)

