"""
Utility script to check the status of the analysis database
"""
import sqlite3
import pandas as pd
from pathlib import Path
from datetime import datetime


def check_status(db_path):
    """
    Check the status of the analysis database.
    
    Args:
        db_path: Path to SQLite database
    """
    if not Path(db_path).exists():
        print(f"Database not found at {db_path}")
        print("Run Phase 1 first to create the database.")
        return
    
    conn = sqlite3.connect(db_path)
    
    print("=" * 60)
    print("SIGMA Analysis Database Status")
    print("=" * 60)
    
    # Check which tables exist
    cursor = conn.cursor()
    cursor.execute("""
        SELECT name FROM sqlite_master 
        WHERE type='table' 
        ORDER BY name
    """)
    tables = [row[0] for row in cursor.fetchall()]
    
    print(f"\nTables in database: {', '.join(tables)}")
    
    # Phase 1 status
    if 'commits' in tables:
        commit_count = pd.read_sql("SELECT COUNT(*) as count FROM commits", conn).iloc[0]['count']
        file_commit_count = pd.read_sql("SELECT COUNT(*) as count FROM commit_files", conn).iloc[0]['count']
        print(f"\nPhase 1 (Commits):")
        print(f"  - Commits: {commit_count}")
        print(f"  - File-commit pairs: {file_commit_count}")
    else:
        print("\nPhase 1: Not started")
    
    # Phase 2 status
    if 'rule_versions' in tables:
        version_count = pd.read_sql("SELECT COUNT(*) as count FROM rule_versions", conn).iloc[0]['count']
        file_count = pd.read_sql("SELECT COUNT(DISTINCT file_path) as count FROM rule_versions", conn).iloc[0]['count']
        parsed_count = pd.read_sql("""
            SELECT COUNT(*) as count FROM rule_versions 
            WHERE rule_id IS NOT NULL
        """, conn).iloc[0]['count']
        print(f"\nPhase 2 (Snapshots):")
        print(f"  - Rule versions: {version_count}")
        print(f"  - Unique files: {file_count}")
        print(f"  - Parsed versions: {parsed_count}")
    else:
        print("\nPhase 2: Not started")
    
    # Phase 3 status
    if 'rule_versions' in tables:
        parse_error_count = pd.read_sql("""
            SELECT COUNT(*) as count FROM rule_versions 
            WHERE parse_error = 1
        """, conn).iloc[0]['count']
        print(f"\nPhase 3 (YAML Parsing):")
        print(f"  - Parse errors: {parse_error_count}")
    else:
        print("\nPhase 3: Not started")
    
    # Phase 4 status
    if 'version_diffs' in tables:
        diff_count = pd.read_sql("SELECT COUNT(*) as count FROM version_diffs", conn).iloc[0]['count']
        print(f"\nPhase 4 (Diffs):")
        print(f"  - Diffs computed: {diff_count}")
    else:
        print("\nPhase 4: Not started")
    
    # Quick stats if data exists
    if 'commits' in tables:
        print("\n" + "=" * 60)
        print("Quick Statistics")
        print("=" * 60)
        
        # Date range
        date_range = pd.read_sql("""
            SELECT MIN(commit_datetime) as min_date, MAX(commit_datetime) as max_date
            FROM commits
        """, conn)
        print(f"Date range: {date_range.iloc[0]['min_date']} to {date_range.iloc[0]['max_date']}")
        
        # Top 3 most edited files
        if 'commit_files' in tables:
            top_files = pd.read_sql("""
                SELECT file_path, COUNT(*) as count
                FROM commit_files
                GROUP BY file_path
                ORDER BY count DESC
                LIMIT 3
            """, conn)
            print("\nTop 3 most edited files:")
            for idx, row in top_files.iterrows():
                print(f"  {row['file_path']}: {row['count']} edits")
    
    conn.close()
    print("\n" + "=" * 60)


if __name__ == "__main__":
    import sys
    db_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("../data/sigma_analysis.db")
    
    check_status(db_path)

