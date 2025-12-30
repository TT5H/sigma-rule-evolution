"""
Phase 1: Extract commit history for rule files
Goal: Build a table of (commit → file touched) + metadata
"""
import sqlite3
from pathlib import Path
from datetime import datetime
from pydriller import Repository
import pandas as pd
from tqdm import tqdm


def extract_commit_history(repo_path, db_path):
    """
    Extract all commits that touch YAML rule files.
    
    Args:
        repo_path: Path to the cloned SIGMA repository
        db_path: Path to SQLite database
    """
    print("Phase 1: Extracting commit history for rule files...")
    
    # Connect to database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS commits (
            commit_hash TEXT PRIMARY KEY,
            author_name TEXT,
            author_email TEXT,
            commit_datetime TEXT,
            commit_message TEXT
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS commit_files (
            commit_hash TEXT,
            file_path TEXT,
            PRIMARY KEY (commit_hash, file_path),
            FOREIGN KEY (commit_hash) REFERENCES commits(commit_hash)
        )
    """)
    
    conn.commit()
    
    # Get existing commits to avoid duplicates
    existing_commits = set(pd.read_sql("SELECT commit_hash FROM commits", conn)['commit_hash'].tolist())
    
    # Traverse repository
    repo = Repository(str(repo_path))
    
    commit_count = 0
    file_count = 0
    
    print("Scanning repository commits...")
    for commit in tqdm(repo.traverse_commits()):
        commit_hash = commit.hash
        
        # Skip if already processed
        if commit_hash in existing_commits:
            continue
        
        # Check if commit touches any YAML rule files
        yaml_files = []
        for modified_file in commit.modified_files:
            if modified_file.filename.endswith('.yml') or modified_file.filename.endswith('.yaml'):
                # Only include files in rules directories (typical SIGMA structure)
                # For deleted files, use old_path but only if we can get content from previous commit
                # For added/modified files, use new_path
                if modified_file.new_path:
                    # File was added or modified - use new_path
                    file_path = modified_file.new_path
                elif modified_file.old_path:
                    # File was deleted - we still want to track it, but will need to get from previous commit
                    file_path = modified_file.old_path
                else:
                    continue
                
                # Normalize path separators
                file_path = file_path.replace('\\', '/')
                
                if 'rules' in file_path or file_path.startswith('rules/'):
                    yaml_files.append(file_path)
        
        # Only process commits that touch rule files
        if yaml_files:
            # Insert commit
            cursor.execute("""
                INSERT OR REPLACE INTO commits 
                (commit_hash, author_name, author_email, commit_datetime, commit_message)
                VALUES (?, ?, ?, ?, ?)
            """, (
                commit_hash,
                commit.author.name,
                commit.author.email,
                commit.author_date.isoformat(),
                commit.msg
            ))
            
            # Insert file associations
            for file_path in yaml_files:
                cursor.execute("""
                    INSERT OR REPLACE INTO commit_files (commit_hash, file_path)
                    VALUES (?, ?)
                """, (commit_hash, file_path))
                file_count += 1
            
            commit_count += 1
            
            # Commit every 100 commits for performance
            if commit_count % 100 == 0:
                conn.commit()
    
    conn.commit()
    conn.close()
    
    print(f"\nPhase 1 Complete:")
    print(f"  - Processed {commit_count} commits")
    print(f"  - Found {file_count} file-commit associations")
    
    return commit_count, file_count


if __name__ == "__main__":
    import sys
    repo_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("../sigma")
    db_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("../data/sigma_analysis.db")
    
    db_path.parent.mkdir(parents=True, exist_ok=True)
    
    extract_commit_history(repo_path, db_path)

