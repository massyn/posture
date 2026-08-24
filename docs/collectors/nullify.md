# Nullify

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `token` | `NULLIFY_TOKEN` |
| `endpoint` | `NULLIFY_ENDPOINT` |
| `github_owner_id` | `NULLIFY_GITHUB_OWNER_ID` |


## Example

```python
from posture import CCM

ccm = CCM("nullify")  # credentials from NULLIFY_TOKEN, NULLIFY_ENDPOINT, NULLIFY_GITHUB_OWNER_ID
df = ccm.collect("repositories")
df = ccm.collect("sast_events")
df = ccm.collect("sca_events")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("nullify")  # credentials from NULLIFY_TOKEN, NULLIFY_ENDPOINT, NULLIFY_GITHUB_OWNER_ID

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [repositories](#repositories)
- [sast_events](#sast_events)
- [sca_events](#sca_events)

### repositories

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `full_name` | `str` |
| `private` | `bool` |
| `default_branch` | `str` |
| `provider` | `str` |
| `last_scanned_at` | `datetime` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |

### sast_events

| Column | Type |
| --- | --- |
| `id` | `str` |
| `type` | `str` |
| `finding_id` | `str` |
| `repository_name` | `str` |
| `repository_full_name` | `str` |
| `rule_id` | `str` |
| `cwe_id` | `str` |
| `severity` | `str` |
| `status` | `str` |
| `title` | `str` |
| `description` | `str` |
| `file_path` | `str` |
| `created_at` | `datetime` |

### sca_events

| Column | Type |
| --- | --- |
| `id` | `str` |
| `type` | `str` |
| `finding_id` | `str` |
| `repository_name` | `str` |
| `repository_full_name` | `str` |
| `package_name` | `str` |
| `package_ecosystem` | `str` |
| `package_version` | `str` |
| `cve_id` | `str` |
| `severity` | `str` |
| `status` | `str` |
| `title` | `str` |
| `description` | `str` |
| `created_at` | `datetime` |

