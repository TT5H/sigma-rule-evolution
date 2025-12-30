# Quick Start Guide

## Prerequisites

1. **Python 3.8+** installed
2. **Git** installed (for cloning repository and git operations)

## Setup Steps

### 1. Clone the SIGMA Repository

```bash
git clone https://github.com/SigmaHQ/sigma.git
```

This will create a `sigma/` directory with the full repository history.

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the Analysis Pipeline

#### Option A: Run All Phases (Recommended for first run)

```bash
python main.py --repo-path sigma
```

This will:
- Phase 1: Extract all commits touching rule files
- Phase 2: Build snapshots of each rule at each commit
- Phase 3: Parse YAML into structured fields
- Phase 4: Compute diffs between versions
- Phase 5: Generate initial findings report

#### Option B: Run Phases Incrementally

If you want to run phases separately (useful for debugging or resuming):

```bash
# Phase 1 only
python main.py --repo-path sigma --phase 1

# Phase 2 only (requires Phase 1)
python main.py --repo-path sigma --phase 2

# Phase 3 only (requires Phase 2)
python main.py --repo-path sigma --phase 3

# Phase 4 only (requires Phase 3)
python main.py --repo-path sigma --phase 4

# Phase 5 only (requires Phase 4)
python main.py --repo-path sigma --phase 5
```

#### Option C: Skip Phase 1 (if already extracted)

```bash
python main.py --repo-path sigma --skip-phase1
```

### 4. Check Database Status

To see what's been processed:

```bash
python scripts/check_status.py
```

## Output Locations

- **Database**: `data/sigma_analysis.db` (SQLite database)
- **Reports**: `reports/` directory containing:
  - `summary_report.txt` - Text summary
  - `most_edited_rules.csv` - Top edited rules
  - `top_contributors.csv` - Top contributors
  - `edits_over_time.png` - Timeline visualization
  - `top_contributors.png` - Contributor bar chart
  - `days_since_edit.png` - Lifecycle distribution
  - `change_taxonomy.png` - Change type breakdown

## Expected Runtime

- **Phase 1**: ~5-15 minutes (depends on repository size)
- **Phase 2**: ~30-60 minutes (extracts all file versions)
- **Phase 3**: ~5-10 minutes (YAML parsing)
- **Phase 4**: ~10-20 minutes (diff computation)
- **Phase 5**: <1 minute (report generation)

**Total**: ~1-2 hours for full pipeline on first run

## Troubleshooting

### "Repository not found"
- Make sure you've cloned the SIGMA repository
- Check the path: `python main.py --repo-path /path/to/sigma`

### "Database locked"
- Another process might be using the database
- Wait for previous run to complete

### Out of Memory
- Phase 2 can be memory-intensive
- Consider running phases separately
- The database commits periodically to manage memory

### Git errors
- Ensure git is installed and in PATH
- The repository should have full history (use `git clone`, not download ZIP)

## Next Steps

After the initial run, you can:

1. **Review the reports** in `reports/` directory
2. **Query the database** directly for custom analyses
3. **Re-run Phase 5** to regenerate reports after database updates:
   ```bash
   python main.py --repo-path sigma --phase 5
   ```

## Database Schema

The database contains these main tables:

- `commits` - All commits touching rule files
- `commit_files` - Mapping of commits to files
- `rule_files` - Metadata about each rule file
- `rule_versions` - All versions of each rule
- `version_diffs` - Diffs between consecutive versions

