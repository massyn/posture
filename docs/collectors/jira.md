# Jira

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `endpoint` | `JIRA_ENDPOINT` |

### Optional

| Config key | Environment variable |
| --- | --- |
| `auth_type` | `JIRA_AUTH_TYPE` |
| `email` | `JIRA_EMAIL` |
| `api_token` | `JIRA_API_TOKEN` |
| `personal_access_token` | `JIRA_PERSONAL_ACCESS_TOKEN` |
| `schema_file` | `JIRA_SCHEMA_FILE` |

## Example

```python
from posture import CCM

ccm = CCM("jira")  # credentials from JIRA_ENDPOINT
df = ccm.collect("issues")
df = ccm.collect("projects")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("jira")  # credentials from JIRA_ENDPOINT

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [issues](#issues)
- [projects](#projects)

### issues

| Column | Type |
| --- | --- |
| `id` | `str` |
| `key` | `str` |
| `summary` | `str` |
| `issue_type` | `str` |
| `status` | `str` |
| `priority` | `str` |
| `project_key` | `str` |
| `assignee` | `str` |
| `assignee_email` | `str` |
| `reporter` | `str` |
| `reporter_email` | `str` |
| `labels` | `json` |
| `resolution` | `str` |
| `created` | `datetime` |
| `updated` | `datetime` |
| `resolutiondate` | `datetime` |
| `duedate` | `datetime` |

### projects

| Column | Type |
| --- | --- |
| `id` | `str` |
| `key` | `str` |
| `name` | `str` |
| `project_type_key` | `str` |
| `style` | `str` |
| `is_private` | `bool` |
| `lead` | `str` |

