"""
Main pipeline orchestrator for SIGMA Rule Longitudinal Analysis
"""
import sys
from pathlib import Path
import argparse

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent / "scripts"))

from phase1_extract_commits import extract_commit_history  # type: ignore
from phase2_build_snapshots import build_rule_snapshots  # type: ignore
from phase3_parse_yaml import parse_all_yaml  # type: ignore
from phase4_compute_diffs import compute_all_diffs  # type: ignore
from phase5_generate_report import generate_report  # type: ignore
from phase6_fetch_external_dates import fetch_external_dates  # type: ignore


def main():
    parser = argparse.ArgumentParser(
        description="SIGMA Rule Longitudinal Analysis Pipeline"
    )
    parser.add_argument(
        "--repo-path",
        type=str,
        default="sigma",
        help="Path to cloned SIGMA repository (default: sigma)"
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default="data/sigma_analysis.db",
        help="Path to SQLite database (default: data/sigma_analysis.db)"
    )
    parser.add_argument(
        "--reports-dir",
        type=str,
        default="reports",
        help="Directory for reports (default: reports)"
    )
    parser.add_argument(
        "--phase",
        type=int,
        choices=[1, 2, 3, 4, 5, 6],
        help="Run only a specific phase (1-6). If not specified, runs all phases."
    )
    parser.add_argument(
        "--skip-phase1",
        action="store_true",
        help="Skip Phase 1 (useful if commits already extracted)"
    )
    
    args = parser.parse_args()
    
    repo_path = Path(args.repo_path)
    db_path = Path(args.db_path)
    reports_dir = Path(args.reports_dir)
    
    # Create directories
    db_path.parent.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    # Check if repo exists
    if not repo_path.exists():
        print(f"Error: Repository not found at {repo_path}")
        print("Please clone the SIGMA repository first:")
        print("  git clone https://github.com/SigmaHQ/sigma.git")
        sys.exit(1)
    
    print("=" * 60)
    print("SIGMA Rule Longitudinal Analysis Pipeline")
    print("=" * 60)
    print(f"Repository: {repo_path}")
    print(f"Database: {db_path}")
    print(f"Reports: {reports_dir}")
    print("=" * 60)
    print()
    
    # Run phases
    if args.phase:
        # Run only specified phase
        phases = {args.phase}
    else:
        # Run all phases
        phases = {1, 2, 3, 4, 5, 6}
        if args.skip_phase1:
            phases.remove(1)
    
    if 1 in phases:
        print("\n" + "=" * 60)
        print("PHASE 1: Extract Commit History")
        print("=" * 60)
        extract_commit_history(repo_path, db_path)
    
    if 2 in phases:
        print("\n" + "=" * 60)
        print("PHASE 2: Build Rule Snapshots")
        print("=" * 60)
        build_rule_snapshots(repo_path, db_path)
    
    if 3 in phases:
        print("\n" + "=" * 60)
        print("PHASE 3: Parse YAML")
        print("=" * 60)
        parse_all_yaml(db_path)
    
    if 4 in phases:
        print("\n" + "=" * 60)
        print("PHASE 4: Compute Diffs")
        print("=" * 60)
        compute_all_diffs(db_path)
    
    if 5 in phases:
        print("\n" + "=" * 60)
        print("PHASE 5: Generate Report")
        print("=" * 60)
        generate_report(db_path, reports_dir)
    
    if 6 in phases:
        print("\n" + "=" * 60)
        print("PHASE 6: Fetch External Dates")
        print("=" * 60)
        fetch_external_dates(db_path)
    
    print("\n" + "=" * 60)
    print("Pipeline Complete!")
    print("=" * 60)
    print(f"Database: {db_path}")
    print(f"Reports: {reports_dir}")
    print("=" * 60)


if __name__ == "__main__":
    main()

