"""
Phase 1: Extract commit history for rule files
Goal: Build a table of (commit → file touched) + metadata
"""
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from pydriller import Repository
import pandas as pd
from tqdm import tqdm
import multiprocessing


def extract_commit_history(repo_path, db_path):
    """
    Extract all commits that touch YAML rule files.
    
    Args:
        repo_path: Path to the cloned SIGMA repository
        db_path: Path to SQLite database
    """
    print("Phase 1: Extracting commit history for rule files...")
    
    # Connect to database with optimizations
    conn = sqlite3.connect(db_path, timeout=60.0)
    cursor = conn.cursor()

    # Optimize SQLite for bulk inserts
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA cache_size=100000")  # 100MB cache
    cursor.execute("PRAGMA temp_store=MEMORY")
    cursor.execute("PRAGMA mmap_size=268435456")  # 256MB memory-mapped I/O

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
            change_type TEXT,
            old_path TEXT,
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

    # Use more aggressive batching and CPU count for parallel processing
    batch_size = 500  # Increased from 100
    cpu_count = multiprocessing.cpu_count()

    print(f"Scanning repository commits with {cpu_count} CPU cores...")

    def process_commit_files(commit):
        """Process files for a single commit (CPU-intensive part)."""
        yaml_files = []
        for modified_file in commit.modified_files:
            if modified_file.filename.endswith('.yml') or modified_file.filename.endswith('.yaml'):
                # Determine file path
                if modified_file.new_path:
                    file_path = modified_file.new_path
                elif modified_file.old_path:
                    file_path = modified_file.old_path
                else:
                    continue

                # Normalize path separators
                file_path = file_path.replace('\\', '/')

                # Only include files in rules directories
                if 'rules' in file_path or file_path.startswith('rules/'):
                    # Capture change metadata with consistent A/M/D/R format
                    raw_change_type = modified_file.change_type.name  # e.g. ADD/MODIFY/DELETE/RENAME
                    change_type_map = {
                        "ADD": "A",
                        "MODIFY": "M",
                        "DELETE": "D",
                        "RENAME": "R"
                    }
                    change_type = change_type_map.get(raw_change_type, raw_change_type)  # fallback to raw if unknown
                    old_path = modified_file.old_path.replace('\\', '/') if modified_file.old_path else None

                    yaml_files.append({
                        'file_path': file_path,
                        'change_type': change_type,
                        'old_path': old_path
                    })

        return yaml_files

    # Prepare batch inserts
    commits_batch = []
    files_batch = []

    for commit in tqdm(repo.traverse_commits()):
        commit_hash = commit.hash

        # Skip if already processed
        if commit_hash in existing_commits:
            continue

        # Process files for this commit
        yaml_files = process_commit_files(commit)

        # Only process commits that touch rule files
        if yaml_files:
            # Add to batch
            commits_batch.append((
                commit_hash,
                commit.author.name,
                commit.author.email,
                commit.author_date.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z'),
                commit.msg
            ))

            # Add file associations to batch with change metadata
            for file_data in yaml_files:
                files_batch.append((
                    commit_hash,
                    file_data['file_path'],
                    file_data['change_type'],
                    file_data['old_path']
                ))
                file_count += 1

            commit_count += 1

            # Commit in larger batches for better performance
            if commit_count % batch_size == 0:
                # Bulk insert commits
                cursor.executemany("""
                    INSERT OR REPLACE INTO commits
                    (commit_hash, author_name, author_email, commit_datetime, commit_message)
                    VALUES (?, ?, ?, ?, ?)
                """, commits_batch)

                # Bulk insert file associations with change metadata
                cursor.executemany("""
                    INSERT OR REPLACE INTO commit_files
                    (commit_hash, file_path, change_type, old_path)
                    VALUES (?, ?, ?, ?)
                """, files_batch)

                conn.commit()
                commits_batch = []
                files_batch = []

    # Final batch commit
    if commits_batch:
        cursor.executemany("""
            INSERT OR REPLACE INTO commits
            (commit_hash, author_name, author_email, commit_datetime, commit_message)
            VALUES (?, ?, ?, ?, ?)
        """, commits_batch)

        cursor.executemany("""
            INSERT OR REPLACE INTO commit_files
            (commit_hash, file_path, change_type, old_path)
            VALUES (?, ?, ?, ?)
        """, files_batch)

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

