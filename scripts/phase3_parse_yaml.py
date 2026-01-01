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
import argparse
from typing import Optional, Dict, Any


class SigmaYamlLoader(yaml.SafeLoader):
    """SafeLoader that ignores unknown !tags instead of failing."""
    pass


def _ignore_unknown_tag(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    return None


# Only ignore custom tags like !foo
SigmaYamlLoader.add_multi_constructor("!", _ignore_unknown_tag)


def _clean_yaml_text(s: str) -> str:
    # Common "real-world repo" issues:
    # - BOM
    # - tabs used for indentation
    # - CRLF
    s = s.lstrip("\ufeff").replace("\r\n", "\n")
    if "\t" in s:
        s = s.replace("\t", "    ")
    return s


def extract_rule_fields(yaml_text) -> Optional[Dict[str, Any]]:
    """
    Extract structured fields from YAML rule.

    Returns:
        dict with extracted fields, or None if parsing fails
    """
    try:
        rule_data = yaml.load(_clean_yaml_text(yaml_text), Loader=SigmaYamlLoader)
        if not isinstance(rule_data, dict):
            return None
        
        # Extract fields
        result = {
            'rule_id': rule_data.get('id'),
            'title': rule_data.get('title'),
            'description': rule_data.get('description'),  # Rule description text
            'status': rule_data.get('status'),
            'level': rule_data.get('level'),
            'author': rule_data.get('author'),  # YAML-level author field
            'yaml_date': rule_data.get('date'),  # YAML-level date field (creation date)
            'yaml_modified': rule_data.get('modified'),  # YAML-level modified date
            'logsource_product': None,
            'logsource_category': None,
            'logsource_service': None,
            'tags': None,
            '[references]': None,
            'falsepositives': None,
            'detection': None,
            'related': None,  # Related rules/techniques
            'parse_error': 0,
            'parse_error_msg': None,
            'parse_error_type': None
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
        
        # Extract related rules/techniques - always convert to JSON string
        related = rule_data.get('related', [])
        if isinstance(related, (list, dict)):
            result['related'] = json.dumps(related)
        else:
            result['related'] = None
        
        return result
        
    except Exception as e:
        return {
            'rule_id': None,
            'title': None,
            'description': None,
            'status': None,
            'level': None,
            'author': None,
            'yaml_date': None,
            'yaml_modified': None,
            'logsource_product': None,
            'logsource_category': None,
            'logsource_service': None,
            'tags': None,
            '[references]': None,
            'falsepositives': None,
            'detection': None,
            'related': None,
            'parse_error': 1,
            'parse_error_msg': (str(e)[:1500] if str(e) else None),
            'parse_error_type': e.__class__.__name__
        }


def parse_all_yaml(db_path, retry_errors: bool = False):
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
        cursor.execute("ALTER TABLE rule_versions ADD COLUMN parse_error_msg TEXT")
    except sqlite3.OperationalError:
        pass

    try:
        cursor.execute("ALTER TABLE rule_versions ADD COLUMN parse_error_type TEXT")
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute("ALTER TABLE rule_versions ADD COLUMN author TEXT")
    except sqlite3.OperationalError:
        pass

    # Note: We do NOT add date/modified columns - only use yaml_date/yaml_modified for YAML metadata
    # commit_datetime is already created by Phase 2 and contains git timeline info

    try:
        cursor.execute("ALTER TABLE rule_versions ADD COLUMN description TEXT")
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute("ALTER TABLE rule_versions ADD COLUMN related TEXT")
    except sqlite3.OperationalError:
        pass
    
    conn.commit()
    
    # Get all unparsed versions (skip deletions)
    base_sql = """
        SELECT file_path, commit_hash, yaml_text
        FROM rule_versions
        WHERE yaml_text IS NOT NULL
          AND event_type != 'deleted'
          AND (
                (rule_id IS NULL OR author IS NULL OR description IS NULL)
                OR parse_error IS NULL
              )
        ORDER BY commit_datetime
    """
    # Default behavior: do NOT keep retrying known failures forever.
    if not retry_errors:
        base_sql = base_sql.replace(")", ") AND (parse_error IS NULL OR parse_error = 0)")
    df = pd.read_sql(base_sql, conn)
    
    print(f"Parsing {len(df)} rule versions...")
    
    parsed_ok = 0
    errors = 0
    
    for _, row in tqdm(df.iterrows(), total=len(df), desc="Parsing YAML"):
        file_path = row['file_path']
        commit_hash = row['commit_hash']
        yaml_text = row['yaml_text']
        
        fields = extract_rule_fields(yaml_text)

        if fields is None:
            errors += 1
            continue

        if fields.get('parse_error') == 1:
            errors += 1
        else:
            parsed_ok += 1
        
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
        
        # Handle related field (may be list/dict)
        related_val = fields.get('related')
        if related_val is not None:
            if isinstance(related_val, str):
                pass
            elif isinstance(related_val, (list, dict)):
                related_val = json.dumps(related_val)
            else:
                related_val = str(related_val)
        
        # Final safety check - ensure no lists/dicts remain
        params = (
            fields.get('rule_id'),
            fields.get('title'),
            fields.get('description'),  # Rule description
            fields.get('status'),
            fields.get('level'),
            fields.get('author'),  # YAML-level author
            fields.get('yaml_date'),  # YAML-level date
            fields.get('yaml_modified'),  # YAML-level modified
            fields.get('logsource_product'),
            fields.get('logsource_category'),
            fields.get('logsource_service'),
            tags_val,
            refs_val,
            fp_val,
            det_val,
            related_val,  # Related rules/techniques
            fields.get('parse_error', 0),
            fields.get('parse_error_msg'),
            fields.get('parse_error_type'),
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
                description = ?,
                status = ?,
                level = ?,
                author = ?,
                yaml_date = ?,
                yaml_modified = ?,
                logsource_product = ?,
                logsource_category = ?,
                logsource_service = ?,
                tags = ?,
                [references] = ?,
                falsepositives = ?,
                detection = ?,
                related = ?,
                parse_error = ?,
                parse_error_msg = ?,
                parse_error_type = ?
            WHERE file_path = ? AND commit_hash = ?
        """, tuple(safe_params))
        
        parsed_ok += 1
        
        if (parsed_ok + errors) % 100 == 0:
            conn.commit()
    
    conn.commit()
    conn.close()
    
    print(f"\nPhase 3 Complete:")
    print(f"  - Parsed OK: {parsed_ok}")
    print(f"  - Parse errors: {errors}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("db_path")
    ap.add_argument("--retry-errors", action="store_true",
                    help="Retry rows with parse_error=1 (useful after parser improvements)")
    args = ap.parse_args()
    parse_all_yaml(args.db_path, retry_errors=args.retry_errors)

