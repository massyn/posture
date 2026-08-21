# GitHub

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `token` | `GITHUB_TOKEN` |

### Optional

| Config key | Environment variable |
| --- | --- |
| `endpoint` | `GITHUB_ENDPOINT` |

## Example

```python
from posture import CCM

ccm = CCM("github")  # credentials from GITHUB_TOKEN
df = ccm.collect("branch_protection_rules")
df = ccm.collect("branches")
df = ccm.collect("code_scanning_alerts")
df = ccm.collect("dependabot_alerts")
df = ccm.collect("members")
df = ccm.collect("organizations")
df = ccm.collect("repositories")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("github")  # credentials from GITHUB_TOKEN

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [branch_protection_rules](#branch_protection_rules)
- [branches](#branches)
- [code_scanning_alerts](#code_scanning_alerts)
- [dependabot_alerts](#dependabot_alerts)
- [members](#members)
- [organizations](#organizations)
- [repositories](#repositories)

### branch_protection_rules

| Column | Type |
| --- | --- |
| `org` | `str` |
| `repo` | `str` |
| `branch` | `str` |
| `type` | `str` |
| `ruleset_id` | `str` |
| `ruleset_source_type` | `str` |
| `ruleset_source` | `str` |
| `parameters` | `json` |

### branches

| Column | Type |
| --- | --- |
| `org` | `str` |
| `repo` | `str` |
| `name` | `str` |
| `protected` | `bool` |
| `commit_sha` | `str` |

### code_scanning_alerts

| Column | Type |
| --- | --- |
| `org` | `str` |
| `repo` | `str` |
| `number` | `int` |
| `state` | `str` |
| `rule_id` | `str` |
| `rule_severity` | `str` |
| `rule_security_severity_level` | `str` |
| `rule_description` | `str` |
| `tool_name` | `str` |
| `tool_version` | `str` |
| `location_path` | `str` |
| `location_start_line` | `int` |
| `location_end_line` | `int` |
| `message` | `str` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |
| `fixed_at` | `datetime` |
| `dismissed_at` | `datetime` |
| `dismissed_by` | `str` |
| `dismissed_reason` | `str` |
| `dismissed_comment` | `str` |
| `html_url` | `str` |

### dependabot_alerts

| Column | Type |
| --- | --- |
| `org` | `str` |
| `repo` | `str` |
| `number` | `int` |
| `state` | `str` |
| `package_ecosystem` | `str` |
| `package_name` | `str` |
| `manifest_path` | `str` |
| `scope` | `str` |
| `ghsa_id` | `str` |
| `cve_id` | `str` |
| `summary` | `str` |
| `severity` | `str` |
| `vulnerable_version_range` | `str` |
| `first_patched_version` | `str` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |
| `fixed_at` | `datetime` |
| `dismissed_at` | `datetime` |
| `dismissed_by` | `str` |
| `dismissed_reason` | `str` |
| `dismissed_comment` | `str` |
| `auto_dismissed_at` | `datetime` |
| `html_url` | `str` |

### members

| Column | Type |
| --- | --- |
| `org` | `str` |
| `id` | `str` |
| `login` | `str` |
| `type` | `str` |
| `site_admin` | `bool` |
| `html_url` | `str` |

### organizations

| Column | Type |
| --- | --- |
| `id` | `str` |
| `login` | `str` |
| `description` | `str` |
| `url` | `str` |

### repositories

| Column | Type |
| --- | --- |
| `org` | `str` |
| `id` | `str` |
| `name` | `str` |
| `full_name` | `str` |
| `private` | `bool` |
| `visibility` | `str` |
| `default_branch` | `str` |
| `description` | `str` |
| `language` | `str` |
| `archived` | `bool` |
| `disabled` | `bool` |
| `fork` | `bool` |
| `is_template` | `bool` |
| `topics` | `json` |
| `license_name` | `str` |
| `open_issues_count` | `int` |
| `stargazers_count` | `int` |
| `forks_count` | `int` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |
| `pushed_at` | `datetime` |
| `html_url` | `str` |

