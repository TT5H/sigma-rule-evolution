# SIGMA Rule Longitudinal Analysis - Initial Findings

## 1. Repository Overview

- **Total rule YAML files**: 10,282
- **Total commits touching rules**: 10,727

## 2. Most Edited Rules (Top 10)

1. `rules\windows\process_access\sysmon_in_memory_assembly_execution.yml`: 44 edits
2. `rules\proxy\proxy_ua_apt.yml`: 41 edits
3. `rules\windows\builtin\win_alert_mimikatz_keywords.yml`: 39 edits
4. `rules\windows\image_load\image_load_side_load_from_non_system_location.yml`: 38 edits
5. `rules\windows\powershell\powershell_script\posh_ps_malicious_commandlets.yml`: 37 edits
6. `rules\windows\builtin\win_susp_process_creations.yml`: 33 edits
7. `rules\windows\registry\registry_set\registry_set_asep_reg_keys_modification_currentversion.yml`: 32 edits
8. `rules\windows\powershell\powershell_cmdline_specific_comb_methods.yml`: 31 edits
9. `rules\windows\process_access\sysmon_cred_dump_lsass_access.yml`: 30 edits
10. `rules\windows\process_access\proc_access_win_direct_syscall_ntopenprocess.yml`: 30 edits

## 3. Top Contributors (Top 10) - Merged by Identity

Contributors are merged by person (not by email) to provide a cleaner view. Some contributors appear under multiple emails (e.g., GitHub noreply + personal). These have been merged for accurate contributor distribution.

1. **Nasreddine Bencherchali**: 12,720 commits (27.8%)
2. **frack113**: 11,242 commits (24.6%)
3. **Florian Roth**: 4,119 commits (9.0%)
4. **phantinuss**: 2,329 commits (5.1%)
5. **github-actions[bot]**: 1,546 commits (3.4%)
6. **Thomas Patzke**: 1,468 commits (3.2%)
7. **Bhabesh Rai**: 811 commits (1.8%)
8. **Swachchhanda Shrawan Poudel**: 601 commits (1.3%)
9. **pbssubhash**: 579 commits (1.3%)
10. **Austin Songer**: 530 commits (1.2%)

## 4. Lifecycle Signals

- **Rules stable for 6+ months**: 8,786 (85.5%)
- **Average days since last edit**: 952.3
- **Median days since last edit**: 1,063.0

The majority of SIGMA rules are stable, with most rules not being modified for over 6 months. This suggests a mature rulebase with established detection patterns.

## 5. Change Taxonomy

Out of 35,410 total changes across all rule versions:

- **Detection logic changes**: 9,748 (27.5%)
- **Metadata changes**: 7,384 (20.9%)
- **Tags changes**: 6,651 (18.8%)
- **References changes**: 3,195 (9.0%)
- **False positives changes**: 1,837 (5.2%)
- **Logsource changes**: 1,277 (3.6%)

Detection logic changes represent the largest category, indicating active refinement of rule detection capabilities. Metadata and tags changes are also significant, suggesting ongoing maintenance and categorization efforts.

## Methodology

This analysis is based on a comprehensive extraction of the SIGMA repository's Git history, parsing all rule versions, and computing diffs between consecutive versions. External references (ATT&CK techniques, CVEs, threat reports) have been extracted and their publication dates fetched for future responsiveness analysis.

## Data Files

All supporting data is available in CSV format:
- `top_edited_rules.csv` - Most frequently edited rules
- `top_contributors_merged.csv` - Top contributors with merged identities
- `edits_per_month.csv` - Commit activity over time
- `change_taxonomy_summary.csv` - Breakdown of change types
- `lifecycle_summary.csv` - Rule stability metrics

## Visualizations

- `edits_over_time.png` - Timeline of rule edits
- `top_contributors.png` - Contributor distribution chart
- `change_taxonomy.png` - Change type distribution
- `days_since_edit.png` - Distribution of rule stability

