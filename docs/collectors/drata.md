# Drata

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `api_key` | `DRATA_API_KEY` |

### Optional

| Config key | Environment variable |
| --- | --- |
| `endpoint` | `DRATA_ENDPOINT` |

## Example

```python
from posture import CCM

ccm = CCM("drata")  # credentials from DRATA_API_KEY
df = ccm.collect("assets")
df = ccm.collect("controls")
df = ccm.collect("devices")
df = ccm.collect("frameworks")
df = ccm.collect("monitors")
df = ccm.collect("personnel")
df = ccm.collect("policies")
df = ccm.collect("vendors")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("drata")  # credentials from DRATA_API_KEY

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [assets](#assets)
- [controls](#controls)
- [devices](#devices)
- [frameworks](#frameworks)
- [monitors](#monitors)
- [personnel](#personnel)
- [policies](#policies)
- [vendors](#vendors)

### assets

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `description` | `str` |
| `type` | `str` |
| `asset_classes` | `json` |
| `owner_email` | `str` |
| `is_confidential` | `bool` |
| `removed_at` | `datetime` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |

### controls

| Column | Type |
| --- | --- |
| `id` | `str` |
| `code` | `str` |
| `name` | `str` |
| `description` | `str` |
| `question` | `str` |
| `activity` | `str` |
| `is_monitored` | `bool` |
| `has_evidence` | `bool` |
| `is_ready` | `bool` |
| `archived_at` | `datetime` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |

### devices

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `serial_number` | `str` |
| `model` | `str` |
| `os_version` | `str` |
| `mac_address` | `str` |
| `source_type` | `str` |
| `agent_version` | `str` |
| `compliance_status` | `str` |
| `personnel_id` | `str` |
| `personnel_email` | `str` |
| `is_encrypted` | `bool` |
| `is_password_manager_installed` | `bool` |
| `is_antivirus_installed` | `bool` |
| `is_screen_lock_enabled` | `bool` |
| `last_checked_at` | `datetime` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |

### frameworks

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `slug` | `str` |
| `description` | `str` |
| `type` | `str` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |

### monitors

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `description` | `str` |
| `check_status` | `str` |
| `enabled` | `bool` |
| `excluded` | `bool` |
| `last_check_at` | `datetime` |
| `next_check_at` | `datetime` |
| `framework_tags` | `json` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |

### personnel

| Column | Type |
| --- | --- |
| `id` | `str` |
| `first_name` | `str` |
| `last_name` | `str` |
| `email` | `str` |
| `job_title` | `str` |
| `employment_status` | `str` |
| `employment_type` | `str` |
| `is_active` | `bool` |
| `is_contractor` | `bool` |
| `start_date` | `datetime` |
| `end_date` | `datetime` |
| `separation_date` | `datetime` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |

### policies

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `description` | `str` |
| `version` | `str` |
| `status` | `str` |
| `approved_at` | `datetime` |
| `last_reviewed_at` | `datetime` |
| `renewal_date` | `datetime` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |

### vendors

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `description` | `str` |
| `website` | `str` |
| `status` | `str` |
| `risk_status` | `str` |
| `criticality` | `str` |
| `tier` | `str` |
| `contact_name` | `str` |
| `contact_email` | `str` |
| `has_dpa` | `bool` |
| `has_security_review` | `bool` |
| `renewal_date` | `datetime` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |

