# Vanta

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `client_id` | `VANTA_CLIENT_ID` |
| `client_secret` | `VANTA_CLIENT_SECRET` |


## Example

```python
from posture import CCM

ccm = CCM("vanta")  # credentials from VANTA_CLIENT_ID, VANTA_CLIENT_SECRET
df = ccm.collect("controls")
df = ccm.collect("documents")
df = ccm.collect("frameworks")
df = ccm.collect("groups")
df = ccm.collect("integrations")
df = ccm.collect("monitored_computers")
df = ccm.collect("people")
df = ccm.collect("tests")
df = ccm.collect("vulnerabilities")
df = ccm.collect("vulnerability_remediations")
df = ccm.collect("vulnerable_assets")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("vanta")  # credentials from VANTA_CLIENT_ID, VANTA_CLIENT_SECRET

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [controls](#controls)
- [documents](#documents)
- [frameworks](#frameworks)
- [groups](#groups)
- [integrations](#integrations)
- [monitored_computers](#monitored_computers)
- [people](#people)
- [tests](#tests)
- [vulnerabilities](#vulnerabilities)
- [vulnerability_remediations](#vulnerability_remediations)
- [vulnerable_assets](#vulnerable_assets)

### controls

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `description` | `str` |
| `question` | `str` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |
| `deleted_at` | `datetime` |

### documents

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `description` | `str` |
| `document_type` | `str` |
| `is_archived` | `bool` |
| `owner_id` | `str` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |

### frameworks

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `description` | `str` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |

### groups

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `source` | `str` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |

### integrations

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `display_name` | `str` |
| `connection_id` | `str` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |

### monitored_computers

| Column | Type |
| --- | --- |
| `id` | `str` |
| `owner_id` | `str` |
| `owner_email` | `str` |
| `owner_name` | `str` |
| `device_type` | `str` |
| `os_version` | `str` |
| `agent_version` | `str` |
| `is_encrypted` | `bool` |
| `firewall_enabled` | `bool` |
| `screen_lock_enabled` | `bool` |
| `auto_update_enabled` | `bool` |
| `last_pinged_at` | `datetime` |

### people

| Column | Type |
| --- | --- |
| `id` | `str` |
| `email` | `str` |
| `full_name` | `str` |
| `given_name` | `str` |
| `family_name` | `str` |
| `is_vanta_owner` | `bool` |
| `employment_status` | `str` |
| `hire_date` | `datetime` |
| `end_date` | `datetime` |

### tests

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `description` | `str` |
| `status` | `str` |
| `entity_type` | `str` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |

### vulnerabilities

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `description` | `str` |
| `severity` | `str` |
| `cve` | `str` |
| `asset_id` | `str` |
| `status` | `str` |
| `detected_at` | `datetime` |
| `remediate_by` | `datetime` |

### vulnerability_remediations

| Column | Type |
| --- | --- |
| `id` | `str` |
| `vulnerability_id` | `str` |
| `asset_id` | `str` |
| `status` | `str` |
| `remediated_at` | `datetime` |

### vulnerable_assets

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `type` | `str` |
| `provider` | `str` |
| `vulnerability_count` | `int` |

