"""
Phase 2: Build rule snapshot database
Goal: Reconstruct every version of each rule at every commit where it changed
"""
import sqlite3
from pathlib import Path
from pydriller import Repository
import pandas as pd
from tqdm import tqdm
import subprocess
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import time


def get_file_content_at_commit(repo_path, commit_hash, file_path, try_parent=False):
    """
    Get file content at a specific commit using git cat-file (faster than git show).
    
    Args:
        repo_path: Path to repository
        commit_hash: Commit hash
        file_path: File path relative to repo root
        try_parent: If True, try parent commit if file not found
    
    Returns:
        File content as string, or None if file doesn't exist at that commit
    """
    try:
        # Normalize path separators for Windows (git always uses forward slashes)
        normalized_path = file_path.replace('\\', '/').replace('//', '/')
        
        commits_to_try = [commit_hash]
        if try_parent:
            # Try parent commit if file was deleted
            commits_to_try.append(f'{commit_hash}^')
        
        for commit_ref in commits_to_try:
            # Use git cat-file for better performance (direct object access)
            # First get the tree object, then the blob
            result = subprocess.run(
                ['git', 'cat-file', '-p', f'{commit_ref}:{normalized_path}'],
                cwd=str(repo_path),
                capture_output=True,
                text=False,  # Get bytes first to handle encoding properly
                timeout=5,  # Reduced timeout since cat-file is faster
                shell=False,
                env={**os.environ, 'GIT_TERMINAL_PROMPT': '0', 'GIT_LFS_SKIP_SMUDGE': '1'}  # Skip LFS for speed
            )
            if result.returncode == 0 and result.stdout:
                # Try to decode as UTF-8, fallback with error handling
                try:
                    return result.stdout.decode('utf-8')
                except UnicodeDecodeError:
                    # Fallback for files with non-UTF-8 encoding
                    return result.stdout.decode('utf-8', errors='replace')
        
        # File doesn't exist at this commit or parent
        return None
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None


def process_file_commits(args):
    """
    Process all commits for a single file (for parallel processing).
    
    Args:
        args: Tuple of (file_path, commits_df, repo_path, db_path)
    
    Returns:
        Tuple of (processed_count, error_count)
    """
    file_path, commits_df, repo_path, db_path = args
    
    # Use a separate connection for each thread with optimized settings
    conn = sqlite3.connect(db_path, timeout=60.0)
    # Optimize SQLite for bulk inserts
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=10000")
    cursor = conn.cursor()
    
    processed = 0
    errors = 0
    
    first_seen = commits_df.iloc[0]['commit_datetime']
    last_seen = commits_df.iloc[-1]['commit_datetime']
    
    # Update rule_files table
    cursor.execute("""
        INSERT OR REPLACE INTO rule_files (file_path, first_seen_date, last_seen_date)
        VALUES (?, ?, ?)
    """, (file_path, first_seen, last_seen))
    
    # Batch check which commits are already processed (safer parameterized query)
    commit_hashes = commits_df['commit_hash'].tolist()
    if commit_hashes:
        # Use parameterized query safely
        placeholders = ','.join(['?' for _ in commit_hashes])
        cursor.execute(f"""
            SELECT commit_hash FROM rule_versions 
            WHERE file_path = ? AND commit_hash IN ({placeholders}) AND yaml_text IS NOT NULL
        """, [file_path] + commit_hashes)
        existing_commits = {row[0] for row in cursor.fetchall()}
    else:
        existing_commits = set()
    
    # Prepare batch inserts
    batch_inserts = []
    
    # Process each commit for this file
    for _, row in commits_df.iterrows():
        commit_hash = row['commit_hash']
        date = row['commit_datetime']
        
        # Skip if already processed
        if commit_hash in existing_commits:
            continue
        
        # Get file content at this commit
        # Try parent commit if file doesn't exist (handles deletions)
        yaml_text = get_file_content_at_commit(repo_path, commit_hash, file_path, try_parent=True)
        
        if yaml_text is None:
            # File doesn't exist at this commit or parent - this is normal for deleted files
            errors += 1
            continue
        
        # Add to batch
        batch_inserts.append((file_path, commit_hash, date, yaml_text))
        processed += 1
        
        # Execute batch inserts periodically
        if len(batch_inserts) >= 50:
            cursor.executemany("""
                INSERT OR REPLACE INTO rule_versions
                (file_path, commit_hash, date, yaml_text)
                VALUES (?, ?, ?, ?)
            """, batch_inserts)
            conn.commit()
            batch_inserts = []
    
    # Insert remaining batch
    if batch_inserts:
        cursor.executemany("""
            INSERT OR REPLACE INTO rule_versions
            (file_path, commit_hash, date, yaml_text)
            VALUES (?, ?, ?, ?)
        """, batch_inserts)
    
    conn.commit()
    conn.close()
    
    return processed, errors


def build_rule_snapshots(repo_path, db_path):
    """
    Build database of all rule versions at each commit.
    
    Args:
        repo_path: Path to cloned SIGMA repository
        db_path: Path to SQLite database
    """
    print("Phase 2: Building rule snapshot database...")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS rule_files (
            file_path TEXT PRIMARY KEY,
            first_seen_date TEXT,
            last_seen_date TEXT
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS rule_versions (
            file_path TEXT,
            commit_hash TEXT,
            date TEXT,
            yaml_text TEXT,
            rule_id TEXT,
            title TEXT,
            status TEXT,
            logsource_product TEXT,
            logsource_category TEXT,
            tags TEXT,
            [references] TEXT,
            PRIMARY KEY (file_path, commit_hash),
            FOREIGN KEY (commit_hash) REFERENCES commits(commit_hash)
        )
    """)
    
    # Create indexes for faster lookups
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_rule_versions_file_commit 
        ON rule_versions(file_path, commit_hash, yaml_text)
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_rule_versions_commit 
        ON rule_versions(commit_hash)
    """)
    
    conn.commit()
    
    # Get all commit-file pairs
    df = pd.read_sql("""
        SELECT cf.commit_hash, cf.file_path, c.commit_datetime
        FROM commit_files cf
        JOIN commits c ON cf.commit_hash = c.commit_hash
        ORDER BY c.commit_datetime, cf.file_path
    """, conn)
    
    print(f"Processing {len(df)} file-commit pairs...")
    
    # Test a sample file first to diagnose issues
    if len(df) > 0:
        sample_file = df.iloc[0]['file_path']
        sample_commit = df.iloc[0]['commit_hash']
        print(f"\nTesting sample: {sample_file} at commit {sample_commit[:8]}...")
        test_content = get_file_content_at_commit(repo_path, sample_commit, sample_file, try_parent=True)
        if test_content:
            print(f"  ✓ Success! Got {len(test_content)} characters")
        else:
            print(f"  ⚠ File not found, trying more samples...")
            # Try a few more samples
            for i in range(1, min(10, len(df))):
                test_file = df.iloc[i]['file_path']
                test_commit = df.iloc[i]['commit_hash']
                test_content = get_file_content_at_commit(repo_path, test_commit, test_file, try_parent=True)
                if test_content:
                    print(f"  ✓ Found working sample: {test_file} at {test_commit[:8]} ({len(test_content)} chars)")
                    break
    
    conn.close()
    
    # Prepare data for parallel processing
    file_groups = []
    for file_path, group in df.groupby('file_path'):
        commits = group.sort_values('commit_datetime')
        file_groups.append((file_path, commits, repo_path, db_path))
    
    print(f"\nProcessing {len(file_groups)} files with parallel workers...")
    
    # Use ThreadPoolExecutor for I/O-bound operations (git commands)
    # Increase workers significantly for I/O-bound operations
    # Git operations are I/O bound, so we can use many more workers
    cpu_count = os.cpu_count() or 4
    max_workers = min(32, cpu_count * 4)  # More aggressive parallelization
    total_processed = 0
    total_errors = 0
    
    print(f"Using {max_workers} parallel workers...")
    
    # Optimize database for concurrent access and performance
    temp_conn = sqlite3.connect(db_path)
    temp_conn.execute("PRAGMA journal_mode=WAL")
    temp_conn.execute("PRAGMA synchronous=NORMAL")
    temp_conn.execute("PRAGMA cache_size=20000")
    temp_conn.execute("PRAGMA temp_store=MEMORY")
    temp_conn.execute("PRAGMA mmap_size=268435456")  # 256MB memory-mapped I/O
    temp_conn.close()
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_file = {
            executor.submit(process_file_commits, args): args[0] 
            for args in file_groups
        }
        
        # Process completed tasks with progress bar
        for future in tqdm(as_completed(future_to_file), total=len(file_groups), desc="Processing files"):
            file_path = future_to_file[future]
            try:
                processed, errors = future.result()
                total_processed += processed
                total_errors += errors
            except Exception as e:
                # Log error but continue
                total_errors += 1
    
    print(f"\nPhase 2 Complete:")
    print(f"  - Processed {total_processed} rule versions")
    print(f"  - Errors: {total_errors}")


if __name__ == "__main__":
    import sys
    repo_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("../sigma")
    db_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("../data/sigma_analysis.db")
    
    build_rule_snapshots(repo_path, db_path)

