# Snyk

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `token` | `SNYK_TOKEN` |

## Example

```python
from posture import CCM

ccm = CCM("snyk")  # credentials from SNYK_TOKEN
df = ccm.collect("issues")
df = ccm.collect("members")
df = ccm.collect("organizations")
df = ccm.collect("projects")
df = ccm.collect("targets")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("snyk")  # credentials from SNYK_TOKEN

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [issues](#issues)
- [members](#members)
- [organizations](#organizations)
- [projects](#projects)
- [targets](#targets)

### issues

| Column | Type |
| --- | --- |
| `org_id` | `str` |
| `id` | `str` |
| `title` | `str` |
| `type` | `str` |
| `effective_severity_level` | `str` |
| `status` | `str` |
| `ignored` | `bool` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |
| `project_id` | `str` |

### members

| Column | Type |
| --- | --- |
| `org_id` | `str` |
| `id` | `str` |
| `username` | `str` |
| `name` | `str` |
| `email` | `str` |
| `role` | `str` |
| `active` | `bool` |

### organizations

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `slug` | `str` |
| `group_id` | `str` |

### projects

| Column | Type |
| --- | --- |
| `org_id` | `str` |
| `id` | `str` |
| `name` | `str` |
| `type` | `str` |
| `origin` | `str` |
| `status` | `str` |
| `created` | `datetime` |
| `target_reference` | `str` |
| `business_criticality` | `json` |
| `environment` | `json` |
| `lifecycle` | `json` |
| `tags` | `json` |
| `target_id` | `str` |

### targets

| Column | Type |
| --- | --- |
| `org_id` | `str` |
| `id` | `str` |
| `display_name` | `str` |
| `url` | `str` |
| `is_private` | `bool` |
| `created_at` | `datetime` |
| `integration_type` | `str` |

