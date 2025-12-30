"""
Phase 5: Generate initial findings report
Goal: Produce the "initial findings" package for Prof. Wajih
"""
import sqlite3
import pandas as pd
from pathlib import Path
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
import logging
import sys
import re
import json

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('phase5_generate_report.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


def extract_github_username(email):
    """
    Extract GitHub username from noreply email addresses.
    Patterns:
    - username@users.noreply.github.com
    - +username@users.noreply.github.com
    - number+username@users.noreply.github.com
    """
    if not email or not isinstance(email, str):
        return None
    
    # Pattern: number+username@users.noreply.github.com or +username@users.noreply.github.com
    match = re.search(r'(\d+\+)?([^+@]+)@users\.noreply\.github\.com', email)
    if match:
        return match.group(2)  # Extract username part
    
    # Pattern: username@users.noreply.github.com (without +)
    match = re.search(r'^([^@]+)@users\.noreply\.github\.com$', email)
    if match:
        return match.group(1)
    
    return None


def normalize_name(name):
    """Normalize author name: lowercase, strip whitespace."""
    if not name or not isinstance(name, str):
        return None
    return name.lower().strip()


def load_manual_aliases(aliases_path=None):
    """Load manual alias mappings from JSON file if it exists."""
    if aliases_path is None:
        aliases_path = Path('aliases.json')
    else:
        aliases_path = Path(aliases_path)
    
    if aliases_path.exists():
        try:
            with open(aliases_path, 'r', encoding='utf-8') as f:
                aliases = json.load(f)
            logger.info(f"Loaded {len(aliases)} manual aliases from {aliases_path}")
            return aliases
        except Exception as e:
            logger.warning(f"Could not load aliases file {aliases_path}: {e}")
    
    return {}


def resolve_contributor_identity(row, manual_aliases=None):
    """
    Resolve contributor identity using hybrid approach:
    1. GitHub username (from noreply email)
    2. Manual alias mapping
    3. Normalized name (lowercase, stripped)
    """
    if manual_aliases is None:
        manual_aliases = {}
    
    email = row.get('author_email', '')
    name = row.get('author_name', '')
    
    # Try GitHub username first
    github_username = extract_github_username(email)
    if github_username:
        # Check if this GitHub username has a manual alias
        if github_username in manual_aliases:
            return manual_aliases[github_username]
        return f"gh:{github_username}"
    
    # Check if email or name is in manual aliases
    if email in manual_aliases:
        return manual_aliases[email]
    if name in manual_aliases:
        return manual_aliases[name]
    
    # Fall back to normalized name
    normalized = normalize_name(name)
    if normalized:
        return f"name:{normalized}"
    
    # Last resort: use email
    return f"email:{email}"


def merge_contributor_identities(df_all_contributors, manual_aliases=None):
    """
    Merge contributor identities to count by person, not by email.
    Uses a two-pass approach:
    1. First pass: Extract GitHub usernames and create name-to-username mapping
    2. Second pass: Resolve identities using GitHub username > name mapping > normalized name
    Returns a DataFrame with identity, display_name, and total commit_count.
    """
    if manual_aliases is None:
        manual_aliases = load_manual_aliases()
    
    # First pass: Extract GitHub usernames and build name-to-username mapping
    df_all_contributors['github_username'] = df_all_contributors['author_email'].apply(extract_github_username)
    df_all_contributors['normalized_name'] = df_all_contributors['author_name'].apply(normalize_name)
    
    # Build set of all GitHub usernames we've seen
    all_github_usernames = set()
    for gh_user in df_all_contributors['github_username'].dropna():
        if gh_user:
            all_github_usernames.add(gh_user.lower())
    
    # Build mapping: normalized_name -> github_username (when normalized name matches a GitHub username)
    name_to_gh = {}
    for _, row in df_all_contributors.iterrows():
        norm_name = row['normalized_name']
        if norm_name and norm_name in all_github_usernames:
            # This normalized name matches a GitHub username we've seen
            if norm_name not in name_to_gh:
                name_to_gh[norm_name] = norm_name  # Use the normalized name as the GitHub username
    
    logger.debug(f"Created {len(name_to_gh)} name-to-GitHub mappings")
    
    # Second pass: Resolve identities
    def resolve_identity(row):
        email = row.get('author_email', '')
        name = row.get('author_name', '')
        github_username = row.get('github_username')
        normalized = row.get('normalized_name')
        
        # Check manual aliases first
        if email in manual_aliases:
            return manual_aliases[email]
        if name in manual_aliases:
            return manual_aliases[name]
        if github_username and github_username in manual_aliases:
            return manual_aliases[github_username]
        if normalized and normalized in manual_aliases:
            return manual_aliases[normalized]
        
        # Use GitHub username if available (preferred)
        if github_username:
            return f"gh:{github_username.lower()}"
        
        # Check if normalized name maps to a GitHub username we've seen
        if normalized and normalized in name_to_gh:
            mapped_gh = name_to_gh[normalized]
            return f"gh:{mapped_gh}"
        
        # Fall back to normalized name
        if normalized:
            return f"name:{normalized}"
        
        # Last resort: use email
        return f"email:{email}"
    
    df_all_contributors['identity'] = df_all_contributors.apply(resolve_identity, axis=1)
    
    # Group by identity and aggregate
    def get_display_info(group):
        # Get most common name for this identity
        name_counts = group['author_name'].value_counts()
        most_common_name = name_counts.index[0] if len(name_counts) > 0 else group['author_name'].iloc[0]
        
        # Get all emails for this identity (for reference)
        emails = group['author_email'].unique().tolist()
        
        return pd.Series({
            'display_name': most_common_name.strip() if most_common_name else 'Unknown',
            'commit_count': len(group),
            'emails': ', '.join(emails[:3]) + ('...' if len(emails) > 3 else '')  # Show up to 3 emails
        })
    
    # Group by identity and aggregate (select only needed columns to avoid grouping column issues)
    contributors_by_identity = df_all_contributors[['identity', 'author_name', 'author_email']].groupby('identity').apply(get_display_info).reset_index()
    contributors_by_identity = contributors_by_identity.sort_values('commit_count', ascending=False)
    
    return contributors_by_identity


def generate_report(db_path, reports_dir):
    """
    Generate comprehensive initial findings report.
    
    Args:
        db_path: Path to SQLite database
        reports_dir: Directory to save reports
    """
    logger.info("=" * 60)
    logger.info("Phase 5: Generating initial findings report...")
    logger.info("=" * 60)
    
    try:
        reports_dir = Path(reports_dir)
        reports_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Reports directory: {reports_dir}")
        
        logger.info(f"Connecting to database: {db_path}")
        conn = sqlite3.connect(db_path, timeout=60.0)
        
        # 1. Repo Overview
        logger.info("\n1. Repository Overview")
        logger.info("=" * 50)
        
        try:
            logger.info("Counting total rule files...")
            total_rules = pd.read_sql("SELECT COUNT(DISTINCT file_path) FROM rule_files", conn).iloc[0, 0]
            logger.info(f"Found {total_rules} unique rule files")
            
            logger.info("Counting total commits...")
            total_commits = pd.read_sql("SELECT COUNT(*) FROM commits", conn).iloc[0, 0]
            logger.info(f"Found {total_commits} total commits")
            
            print(f"\nTotal rule YAML files: {total_rules}")
            print(f"Total commits touching rules: {total_commits}")
        except Exception as e:
            logger.error(f"Error in repository overview: {e}", exc_info=True)
            raise
        
        # Edits per year/month
        try:
            logger.info("Analyzing edits over time...")
            df_commits = pd.read_sql("""
                SELECT commit_datetime FROM commits
                ORDER BY commit_datetime
            """, conn)
            
            if len(df_commits) == 0:
                logger.warning("No commits found in database")
                raise ValueError("No commits found in database")
            
            df_commits['commit_datetime'] = pd.to_datetime(df_commits['commit_datetime'], utc=True, errors='coerce')
            # Drop rows where datetime conversion failed
            df_commits = df_commits.dropna(subset=['commit_datetime'])
            if len(df_commits) == 0:
                raise ValueError("No valid commit datetimes found after conversion")
            df_commits['year'] = df_commits['commit_datetime'].dt.year
            df_commits['year_month'] = df_commits['commit_datetime'].dt.to_period('M')
            
            edits_per_year = df_commits.groupby('year').size()
            edits_per_month = df_commits.groupby('year_month').size()
            
            logger.info(f"Computed edits per year/month: {len(edits_per_year)} years, {len(edits_per_month)} months")
            
            print(f"\nEdits per year:")
            for year, count in edits_per_year.items():
                print(f"  {year}: {count}")
                logger.info(f"  {year}: {count} commits")
            
            # Export edits per month to CSV
            edits_per_month_df = pd.DataFrame({
                'year_month': edits_per_month.index.astype(str),
                'commit_count': edits_per_month.values
            })
            csv_path = reports_dir / 'edits_per_month.csv'
            edits_per_month_df.to_csv(csv_path, index=False)
            logger.info(f"Saved edits per month to {csv_path}")
            
            # Plot edits over time
            logger.info("Generating edits over time plot...")
            plt.figure(figsize=(12, 6))
            edits_per_month.plot(kind='line', marker='o')
            plt.title('SIGMA Rule Edits Over Time')
            plt.xlabel('Year-Month')
            plt.ylabel('Number of Commits')
            plt.xticks(rotation=45)
            plt.tight_layout()
            plot_path = reports_dir / 'edits_over_time.png'
            plt.savefig(plot_path, dpi=300)
            plt.close()
            logger.info(f"Saved plot to {plot_path}")
        except Exception as e:
            logger.error(f"Error analyzing edits over time: {e}", exc_info=True)
            raise
        
        # 2. Most Edited Rules
        logger.info("\n2. Most Edited Rules")
        logger.info("=" * 50)
        
        try:
            logger.info("Querying most edited rules...")
            most_edited = pd.read_sql("""
                SELECT file_path, COUNT(*) as edit_count
                FROM commit_files
                GROUP BY file_path
                ORDER BY edit_count DESC
                LIMIT 10
            """, conn)
            
            logger.info(f"Found {len(most_edited)} most edited rules")
            
            print("\nTop 10 most-edited rules:")
            for idx, row in most_edited.iterrows():
                print(f"  {idx+1}. {row['file_path']}: {row['edit_count']} edits")
                logger.info(f"  {idx+1}. {row['file_path']}: {row['edit_count']} edits")
            
            csv_path = reports_dir / 'top_edited_rules.csv'
            most_edited.to_csv(csv_path, index=False)
            logger.info(f"Saved most edited rules to {csv_path}")
        except Exception as e:
            logger.error(f"Error analyzing most edited rules: {e}", exc_info=True)
            raise
        
        # 3. Top Contributors
        logger.info("\n3. Top Contributors")
        logger.info("=" * 50)
        
        try:
            logger.info("Querying top contributors...")
            # First, get all commits with author info
            df_all_contributors = pd.read_sql("""
                SELECT c.author_name, c.author_email, c.commit_hash
                FROM commits c
                JOIN commit_files cf ON c.commit_hash = cf.commit_hash
            """, conn)
            
            if len(df_all_contributors) == 0:
                logger.warning("No contributors found")
                raise ValueError("No contributors found in database")
            
            logger.info(f"Found {len(df_all_contributors)} commit-file pairs to analyze")
            
            # Merge contributor identities (by person, not by email)
            logger.info("Merging contributor identities...")
            contributors_by_identity = merge_contributor_identities(df_all_contributors)
            
            # Get top 10
            top_contributors = contributors_by_identity.head(10).copy()
            
            total_rule_commits = len(df_all_contributors)
            
            logger.info(f"Found {len(top_contributors)} top contributors out of {len(contributors_by_identity)} unique identities")
            logger.info(f"Total rule commits: {total_rule_commits}")
            
            print("\nTop 10 contributors (merged by identity):")
            for idx, row in top_contributors.iterrows():
                share = (row['commit_count'] / total_rule_commits) * 100
                print(f"  {idx+1}. {row['display_name']}: {row['commit_count']} commits ({share:.1f}%)")
                logger.info(f"  {idx+1}. {row['display_name']}: {row['commit_count']} commits ({share:.1f}%)")
                logger.debug(f"     Identity: {row['identity']}, Emails: {row['emails']}")
            
            # Prepare CSV output (exclude internal identity column, show display name)
            csv_output = top_contributors[['display_name', 'commit_count', 'emails']].copy()
            csv_output.columns = ['author_name', 'commit_count', 'emails']
            csv_path = reports_dir / 'top_contributors_merged.csv'
            csv_output.to_csv(csv_path, index=False)
            logger.info(f"Saved top contributors to {csv_path}")
            
            # Plot contributor distribution
            logger.info("Generating contributors plot...")
            plt.figure(figsize=(10, 6))
            top_contributors.head(10).plot(x='display_name', y='commit_count', kind='barh')
            plt.title('Top 10 Contributors by Rule File Commits (Merged by Identity)')
            plt.xlabel('Number of Commits')
            plt.ylabel('Contributor')
            plt.tight_layout()
            plot_path = reports_dir / 'top_contributors.png'
            plt.savefig(plot_path, dpi=300)
            plt.close()
            logger.info(f"Saved plot to {plot_path}")
        except Exception as e:
            logger.error(f"Error analyzing top contributors: {e}", exc_info=True)
            raise
        
        # 4. Early Lifecycle Signals
        logger.info("\n4. Early Lifecycle Signals")
        logger.info("=" * 50)
        
        try:
            # Time since last edit
            logger.info("Analyzing lifecycle signals...")
            df_last_edit = pd.read_sql("""
                SELECT file_path, last_seen_date
                FROM rule_files
            """, conn)
            
            if len(df_last_edit) == 0:
                logger.warning("No rule files found for lifecycle analysis")
                raise ValueError("No rule files found")
            
            df_last_edit['last_seen_date'] = pd.to_datetime(df_last_edit['last_seen_date'], utc=True, errors='coerce')
            # Drop rows where datetime conversion failed
            df_last_edit = df_last_edit.dropna(subset=['last_seen_date'])
            if len(df_last_edit) == 0:
                raise ValueError("No valid last_seen_date values found after conversion")
            # Use UTC-aware datetime for comparison
            from datetime import timezone
            now_utc = datetime.now(timezone.utc)
            df_last_edit['days_since_edit'] = (now_utc - df_last_edit['last_seen_date']).dt.days
            
            stable_rules = len(df_last_edit[df_last_edit['days_since_edit'] >= 180])
            stable_percent = (stable_rules / len(df_last_edit)) * 100
            
            logger.info(f"Analyzed {len(df_last_edit)} rules for lifecycle signals")
            logger.info(f"Stable rules (6+ months): {stable_rules} ({stable_percent:.1f}%)")
            
            print(f"Rules stable for 6+ months: {stable_rules} ({stable_percent:.1f}%)")
            print(f"Average days since last edit: {df_last_edit['days_since_edit'].mean():.1f}")
            print(f"Median days since last edit: {df_last_edit['days_since_edit'].median():.1f}")
            
            # Export lifecycle summary to CSV
            lifecycle_summary = pd.DataFrame({
                'metric': [
                    'total_rules',
                    'stable_rules_6plus_months',
                    'stable_percent',
                    'avg_days_since_edit',
                    'median_days_since_edit'
                ],
                'value': [
                    len(df_last_edit),
                    stable_rules,
                    stable_percent,
                    df_last_edit['days_since_edit'].mean(),
                    df_last_edit['days_since_edit'].median()
                ]
            })
            csv_path = reports_dir / 'lifecycle_summary.csv'
            lifecycle_summary.to_csv(csv_path, index=False)
            logger.info(f"Saved lifecycle summary to {csv_path}")
            
            # Distribution plot
            logger.info("Generating lifecycle distribution plot...")
            plt.figure(figsize=(10, 6))
            plt.hist(df_last_edit['days_since_edit'], bins=50, edgecolor='black')
            plt.axvline(180, color='r', linestyle='--', label='6 months')
            plt.title('Distribution of Days Since Last Edit')
            plt.xlabel('Days Since Last Edit')
            plt.ylabel('Number of Rules')
            plt.legend()
            plt.tight_layout()
            plot_path = reports_dir / 'days_since_edit.png'
            plt.savefig(plot_path, dpi=300)
            plt.close()
            logger.info(f"Saved plot to {plot_path}")
        except Exception as e:
            logger.error(f"Error analyzing lifecycle signals: {e}", exc_info=True)
            raise
        
        # 5. Early Change Taxonomy
        logger.info("\n5. Early Change Taxonomy")
        logger.info("=" * 50)
        
        try:
            logger.info("Analyzing change taxonomy...")
            df_diffs = pd.read_sql("""
            SELECT 
                SUM(detection_changed) as detection_changes,
                SUM(logsource_changed) as logsource_changes,
                SUM(tags_changed) as tags_changes,
                SUM(references_changed) as references_changes,
                SUM(falsepositives_changed) as falsepositives_changes,
                SUM(metadata_changed) as metadata_changes,
                COUNT(*) as total_changes
            FROM version_diffs
            """, conn)
            
            if len(df_diffs) == 0 or df_diffs['total_changes'].iloc[0] == 0:
                logger.warning("No diffs found in database. Make sure Phase 4 completed successfully.")
                raise ValueError("No version diffs found in database")
            
            total = df_diffs['total_changes'].iloc[0]
            logger.info(f"Analyzing {total} total changes")
            
            print(f"\nChange type distribution (out of {total} total changes):")
            detection_changes = df_diffs['detection_changes'].iloc[0] or 0
            logsource_changes = df_diffs['logsource_changes'].iloc[0] or 0
            tags_changes = df_diffs['tags_changes'].iloc[0] or 0
            references_changes = df_diffs['references_changes'].iloc[0] or 0
            falsepositives_changes = df_diffs['falsepositives_changes'].iloc[0] or 0
            metadata_changes = df_diffs['metadata_changes'].iloc[0] or 0
            
            print(f"  Detection logic changes: {detection_changes} ({detection_changes/total*100:.1f}%)")
            print(f"  Logsource changes: {logsource_changes} ({logsource_changes/total*100:.1f}%)")
            print(f"  Tags changes: {tags_changes} ({tags_changes/total*100:.1f}%)")
            print(f"  References changes: {references_changes} ({references_changes/total*100:.1f}%)")
            print(f"  False positives changes: {falsepositives_changes} ({falsepositives_changes/total*100:.1f}%)")
            print(f"  Metadata changes: {metadata_changes} ({metadata_changes/total*100:.1f}%)")
            
            logger.info(f"Detection: {detection_changes}, Logsource: {logsource_changes}, Tags: {tags_changes}")
            logger.info(f"References: {references_changes}, FalsePositives: {falsepositives_changes}, Metadata: {metadata_changes}")
            
            # Plot change taxonomy
            logger.info("Generating change taxonomy plot...")
            change_types = ['Detection', 'Logsource', 'Tags', 'References', 'False Positives', 'Metadata']
            change_counts = [
                detection_changes,
                logsource_changes,
                tags_changes,
                references_changes,
                falsepositives_changes,
                metadata_changes
            ]
            
            plt.figure(figsize=(10, 6))
            plt.bar(change_types, change_counts)
            plt.title('Change Type Distribution')
            plt.xlabel('Change Type')
            plt.ylabel('Number of Changes')
            plt.xticks(rotation=45)
            plt.tight_layout()
            plot_path = reports_dir / 'change_taxonomy.png'
            plt.savefig(plot_path, dpi=300)
            plt.close()
            logger.info(f"Saved plot to {plot_path}")
            
            # Export change taxonomy summary to CSV
            change_taxonomy_df = pd.DataFrame({
                'change_type': change_types,
                'count': change_counts,
                'percentage': [c/total*100 for c in change_counts]
            })
            csv_path = reports_dir / 'change_taxonomy_summary.csv'
            change_taxonomy_df.to_csv(csv_path, index=False)
            logger.info(f"Saved change taxonomy summary to {csv_path}")
        except Exception as e:
            logger.error(f"Error analyzing change taxonomy: {e}", exc_info=True)
            raise
        
        # Generate summary report
        try:
            logger.info("Generating summary report...")
            summary_path = reports_dir / 'summary_report.txt'
            with open(summary_path, 'w', encoding='utf-8') as f:
                f.write("SIGMA Rule Longitudinal Analysis - Initial Findings\n")
                f.write("=" * 60 + "\n\n")
                
                f.write("1. Repository Overview\n")
                f.write(f"   Total rule YAML files: {total_rules}\n")
                f.write(f"   Total commits touching rules: {total_commits}\n\n")
                
                f.write("2. Most Edited Rules (Top 10)\n")
                for idx, row in most_edited.iterrows():
                    f.write(f"   {idx+1}. {row['file_path']}: {row['edit_count']} edits\n")
                f.write("\n")
                
                f.write("3. Top Contributors (Top 10) - Merged by Identity\n")
                for idx, row in top_contributors.iterrows():
                    share = (row['commit_count'] / total_rule_commits) * 100
                    f.write(f"   {idx+1}. {row['display_name']}: {row['commit_count']} commits ({share:.1f}%)\n")
                f.write("\n")
                
                f.write("4. Lifecycle Signals\n")
                f.write(f"   Rules stable for 6+ months: {stable_rules} ({stable_percent:.1f}%)\n")
                f.write(f"   Average days since last edit: {df_last_edit['days_since_edit'].mean():.1f}\n\n")
                
                f.write("5. Change Taxonomy\n")
                f.write(f"   Detection logic changes: {detection_changes} ({detection_changes/total*100:.1f}%)\n")
                f.write(f"   Logsource changes: {logsource_changes} ({logsource_changes/total*100:.1f}%)\n")
                f.write(f"   Tags changes: {tags_changes} ({tags_changes/total*100:.1f}%)\n")
                f.write(f"   References changes: {references_changes} ({references_changes/total*100:.1f}%)\n")
                f.write(f"   False positives changes: {falsepositives_changes} ({falsepositives_changes/total*100:.1f}%)\n")
                f.write(f"   Metadata changes: {metadata_changes} ({metadata_changes/total*100:.1f}%)\n")
            
            logger.info(f"Summary report saved to {summary_path}")
            
            conn.close()
            
            logger.info("=" * 60)
            logger.info("Phase 5 Complete:")
            logger.info(f"  - Reports saved to {reports_dir}")
            logger.info(f"  - Summary report: {summary_path}")
            logger.info("=" * 60)
            
            print(f"\nPhase 5 Complete:")
            print(f"  - Reports saved to {reports_dir}")
            print(f"  - Summary report: {summary_path}")
            print(f"  - Check phase5_generate_report.log for detailed logs")
        
        except Exception as e:
            logger.error(f"Error generating summary report: {e}", exc_info=True)
            if 'conn' in locals():
                conn.close()
            raise
    
    except Exception as e:
        logger.error(f"Critical error in generate_report: {e}", exc_info=True)
        print(f"\nError in Phase 5: {e}")
        print("Check phase5_generate_report.log for details")
        if 'conn' in locals():
            conn.close()
        raise


if __name__ == "__main__":
    import sys
    db_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("../data/sigma_analysis.db")
    reports_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("../reports")
    
    generate_report(db_path, reports_dir)

