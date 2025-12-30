# SIGMA Rule Longitudinal Analysis

A comprehensive analysis pipeline for studying the evolution of SIGMA detection rules over time. This project extracts commit history, builds a rule snapshot database, parses YAML content, computes version diffs, and generates reports on rule evolution, contributors, and change patterns.

## Setup

1. Clone the SIGMA repository:
```bash
git clone https://github.com/SigmaHQ/sigma.git
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the analysis pipeline:
```bash
# Run all phases
python main.py

# Run a specific phase
python main.py --phase 5

# Skip Phase 1 if commits already extracted
python main.py --skip-phase1
```

## Project Structure

- `scripts/` - Analysis scripts for each phase
  - `phase1_extract_commits.py` - Extract Git commit history
  - `phase2_build_snapshots.py` - Build rule version snapshots
  - `phase3_parse_yaml.py` - Parse YAML into structured fields
  - `phase4_compute_diffs.py` - Compute version differences
  - `phase5_generate_report.py` - Generate initial findings report
  - `phase6_fetch_external_dates.py` - Fetch external reference dates
- `data/` - SQLite database (`sigma_analysis.db`) and exports
- `reports/` - Generated plots, CSVs, and summary reports
- `main.py` - Main pipeline orchestrator

## Phases

### Phase 1: Extract Commit History
Extracts commit-level metadata for all YAML rule files from Git history.
- **Output**: `commits` and `commit_files` tables in database
- **Key metrics**: Total commits, commits per file

### Phase 2: Build Rule Snapshot Database
Reconstructs every version of each rule at every commit where it changed.
- **Output**: `rule_versions` table with raw YAML content
- **Performance**: 8x faster with parallel processing and batch operations

### Phase 3: Parse YAML into Structured Fields
Converts YAML to structured fields (title, status, tags, references, detection, etc.).
- **Output**: Updated `rule_versions` table with parsed fields
- **Success Rate**: 99.96% (only 0.04% parse errors)

### Phase 4: Compute Diffs Between Versions
Compares consecutive rule versions and classifies change types.
- **Output**: `version_diffs` table with change classifications
- **Change types**: Detection, logsource, tags, references, false positives, metadata

### Phase 5: Generate Initial Findings Report
Produces comprehensive reports with statistics, visualizations, and top lists.
- **Outputs**:
  - `top_edited_rules.csv` - Most frequently edited rules
  - `top_contributors_merged.csv` - Top contributors (merged by identity)
  - `edits_per_month.csv` - Commit activity timeline
  - `change_taxonomy_summary.csv` - Change type breakdown
  - `lifecycle_summary.csv` - Rule stability metrics
  - `INITIAL_FINDINGS.md` - Summary report
  - PNG plots: `edits_over_time.png`, `top_contributors.png`, `change_taxonomy.png`, `days_since_edit.png`

### Phase 6: Fetch External Dates
Extracts and fetches publication dates for ATT&CK techniques, CVEs, and threat reports.
- **Output**: `attack_techniques`, `cves`, `threat_reports`, and `rule_external_refs` tables
- **Purpose**: Enable responsiveness analysis (time between external event and rule update)

## Performance & Reliability

The pipeline has been optimized for high throughput and low error rates:

### Phase 2 Optimizations
- **Processing Speed**: 8x faster (33 minutes → 4 minutes)
- **Throughput**: 5.19 it/s → 41.25 it/s (8x improvement)
- **Success Rate**: 99.99% (45,691/45,696 rule versions successfully extracted)
- **Error Rate**: Reduced from 411 errors to just 5 errors (98.8% reduction)

**Key Optimizations:**
- Switched from `git show` to `git cat-file -p` for faster object access
- Increased parallel workers from 16 to 32
- Implemented batch database operations (executemany for bulk inserts)
- Added database indexes and optimized SQLite settings (WAL mode, larger cache)
- Batch checking existing commits to avoid redundant processing

### Phase 3 Results
- **Success Rate**: 99.96% (42,276/42,294 rule versions successfully parsed)
- **Parse Error Rate**: Only 18 errors (0.04% error rate)
- **Processing Time**: ~2 minutes for 42K+ rule versions

**Improvements:**
- Robust JSON encoding for list/dict fields
- Comprehensive safety checks to ensure SQL-compatible parameters
- Proper handling of edge cases and malformed YAML

