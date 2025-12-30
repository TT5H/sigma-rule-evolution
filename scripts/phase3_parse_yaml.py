"""
Phase 3: Parse YAML into structured fields
Goal: Convert YAML to Python dict and extract consistent fields
"""
import sqlite3
import yaml
import json
from pathlib import Path
import pandas as pd
from tqdm import tqdm


def extract_rule_fields(yaml_text):
    """
    Extract structured fields from YAML rule.
    
    Returns:
        dict with extracted fields, or None if parsing fails
    """
    try:
        rule_data = yaml.safe_load(yaml_text)
        if not isinstance(rule_data, dict):
            return None
        
        # Extract fields
        result = {
            'rule_id': rule_data.get('id'),
            'title': rule_data.get('title'),
            'status': rule_data.get('status'),
            'level': rule_data.get('level'),
            'author': rule_data.get('author'),  # YAML-level author field
            'date': rule_data.get('date'),  # YAML-level date field (creation date)
            'modified': rule_data.get('modified'),  # YAML-level modified date
            'logsource_product': None,
            'logsource_category': None,
            'logsource_service': None,
            'tags': None,
            '[references]': None,
            'falsepositives': None,
            'detection': None,
            'parse_error': 0
        }
        
        # Extract logsource
        logsource = rule_data.get('logsource', {})
        if isinstance(logsource, dict):
            result['logsource_product'] = logsource.get('product')
            result['logsource_category'] = logsource.get('category')
            result['logsource_service'] = logsource.get('service')
        
        # Extract tags (especially ATT&CK) - always convert to JSON string
        # Check isinstance FIRST to catch empty lists
        tags = rule_data.get('tags', [])
        if isinstance(tags, (list, dict)):
            result['tags'] = json.dumps(tags)
        else:
            result['tags'] = None
        
        # Extract references - always convert to JSON string
        references = rule_data.get('references', [])
        if isinstance(references, (list, dict)):
            result['[references]'] = json.dumps(references)
        else:
            result['[references]'] = None
        
        # Extract falsepositives - always convert to JSON string
        falsepositives = rule_data.get('falsepositives', [])
        if isinstance(falsepositives, (list, dict)):
            result['falsepositives'] = json.dumps(falsepositives)
        else:
            result['falsepositives'] = None
        
        # Store detection block (we'll analyze complexity later) - always convert to JSON string
        detection = rule_data.get('detection', {})
        if isinstance(detection, (list, dict)):
            result['detection'] = json.dumps(detection)
        else:
            result['detection'] = None
        
        return result
        
    except Exception as e:
        return {
            'rule_id': None,
            'title': None,
            'status': None,
            'level': None,
            'author': None,
            'date': None,
            'modified': None,
            'logsource_product': None,
            'logsource_category': None,
            'logsource_service': None,
            'tags': None,
            '[references]': None,
            'falsepositives': None,
            'detection': None,
            'parse_error': 1
        }


def parse_all_yaml(db_path):
    """
    Parse all YAML rule versions and update database.
    
    Args:
        db_path: Path to SQLite database
    """
    print("Phase 3: Parsing YAML into structured fields...")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Add columns if they don't exist (for incremental updates)
    try:
        cursor.execute("ALTER TABLE rule_versions ADD COLUMN rule_id TEXT")
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute("ALTER TABLE rule_versions ADD COLUMN title TEXT")
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute("ALTER TABLE rule_versions ADD COLUMN status TEXT")
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute("ALTER TABLE rule_versions ADD COLUMN level TEXT")
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute("ALTER TABLE rule_versions ADD COLUMN logsource_product TEXT")
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute("ALTER TABLE rule_versions ADD COLUMN logsource_category TEXT")
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute("ALTER TABLE rule_versions ADD COLUMN logsource_service TEXT")
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute("ALTER TABLE rule_versions ADD COLUMN tags TEXT")
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute("ALTER TABLE rule_versions ADD COLUMN [references] TEXT")
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute("ALTER TABLE rule_versions ADD COLUMN falsepositives TEXT")
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute("ALTER TABLE rule_versions ADD COLUMN detection TEXT")
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute("ALTER TABLE rule_versions ADD COLUMN parse_error INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute("ALTER TABLE rule_versions ADD COLUMN author TEXT")
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute("ALTER TABLE rule_versions ADD COLUMN date TEXT")
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute("ALTER TABLE rule_versions ADD COLUMN modified TEXT")
    except sqlite3.OperationalError:
        pass
    
    conn.commit()
    
    # Get all unparsed versions (or versions missing new fields)
    df = pd.read_sql("""
        SELECT file_path, commit_hash, yaml_text
        FROM rule_versions
        WHERE (rule_id IS NULL OR parse_error IS NULL OR author IS NULL)
        ORDER BY date
    """, conn)
    
    print(f"Parsing {len(df)} rule versions...")
    
    parsed = 0
    errors = 0
    
    for _, row in tqdm(df.iterrows(), total=len(df), desc="Parsing YAML"):
        file_path = row['file_path']
        commit_hash = row['commit_hash']
        yaml_text = row['yaml_text']
        
        fields = extract_rule_fields(yaml_text)
        
        if fields is None:
            errors += 1
            continue
        
        # Safety check: ensure all list/dict fields are JSON strings (defensive programming)
        # Convert ANY non-string, non-None value to appropriate format
        tags_val = fields.get('tags')
        if tags_val is not None:
            if isinstance(tags_val, str):
                pass  # Already a string
            elif isinstance(tags_val, (list, dict)):
                tags_val = json.dumps(tags_val)
            else:
                tags_val = str(tags_val)  # Convert anything else to string
        
        refs_val = fields.get('[references]')
        if refs_val is not None:
            if isinstance(refs_val, str):
                pass
            elif isinstance(refs_val, (list, dict)):
                refs_val = json.dumps(refs_val)
            else:
                refs_val = str(refs_val)
        
        fp_val = fields.get('falsepositives')
        if fp_val is not None:
            if isinstance(fp_val, str):
                pass
            elif isinstance(fp_val, (list, dict)):
                fp_val = json.dumps(fp_val)
            else:
                fp_val = str(fp_val)
        
        det_val = fields.get('detection')
        if det_val is not None:
            if isinstance(det_val, str):
                pass
            elif isinstance(det_val, (list, dict)):
                det_val = json.dumps(det_val)
            else:
                det_val = str(det_val)
        
        # Final safety check - ensure no lists/dicts remain
        params = (
            fields.get('rule_id'),
            fields.get('title'),
            fields.get('status'),
            fields.get('level'),
            fields.get('author'),  # YAML-level author
            fields.get('date'),  # YAML-level date
            fields.get('modified'),  # YAML-level modified
            fields.get('logsource_product'),
            fields.get('logsource_category'),
            fields.get('logsource_service'),
            tags_val,
            refs_val,
            fp_val,
            det_val,
            fields.get('parse_error', 0),
            file_path,
            commit_hash
        )
        
        # Convert any remaining lists/dicts in params to strings
        safe_params = []
        for p in params:
            if isinstance(p, (list, dict)):
                safe_params.append(json.dumps(p))
            else:
                safe_params.append(p)
        
        # Update database
        cursor.execute("""
            UPDATE rule_versions
            SET rule_id = ?,
                title = ?,
                status = ?,
                level = ?,
                author = ?,
                date = ?,
                modified = ?,
                logsource_product = ?,
                logsource_category = ?,
                logsource_service = ?,
                tags = ?,
                [references] = ?,
                falsepositives = ?,
                detection = ?,
                parse_error = ?
            WHERE file_path = ? AND commit_hash = ?
        """, tuple(safe_params))
        
        parsed += 1
        
        if parsed % 100 == 0:
            conn.commit()
    
    conn.commit()
    conn.close()
    
    print(f"\nPhase 3 Complete:")
    print(f"  - Parsed {parsed} rule versions")
    print(f"  - Parse errors: {errors}")


if __name__ == "__main__":
    import sys
    db_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("../data/sigma_analysis.db")
    
    parse_all_yaml(db_path)

