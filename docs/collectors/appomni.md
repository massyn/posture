# AppOmni

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `access_token` | `APPOMNI_ACCESS_TOKEN` |
| `instance` | `APPOMNI_INSTANCE` |

## Example

```python
from posture import CCM

ccm = CCM("appomni")  # credentials from APPOMNI_ACCESS_TOKEN, APPOMNI_INSTANCE
df = ccm.collect("monitored_services")
df = ccm.collect("open_policy_issues")
df = ccm.collect("policies")
df = ccm.collect("posture_policies")
df = ccm.collect("unified_identities")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("appomni")  # credentials from APPOMNI_ACCESS_TOKEN, APPOMNI_INSTANCE

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [monitored_services](#monitored_services)
- [open_policy_issues](#open_policy_issues)
- [policies](#policies)
- [posture_policies](#posture_policies)
- [unified_identities](#unified_identities)

### monitored_services

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `app_type` | `str` |
| `instance_url` | `str` |
| `status` | `str` |
| `created` | `datetime` |
| `updated` | `datetime` |

### open_policy_issues

| Column | Type |
| --- | --- |
| `id` | `str` |
| `policy_id` | `str` |
| `policy_name` | `str` |
| `severity` | `str` |
| `status` | `str` |
| `monitored_service_id` | `str` |
| `monitored_service_name` | `str` |
| `detected_at` | `datetime` |
| `resolved_at` | `datetime` |

### policies

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `description` | `str` |
| `policy_type` | `str` |
| `severity` | `str` |
| `is_reference` | `bool` |
| `enabled` | `bool` |
| `created` | `datetime` |
| `updated` | `datetime` |

### posture_policies

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `description` | `str` |
| `policy_type` | `str` |
| `severity` | `str` |
| `enabled` | `bool` |
| `created` | `datetime` |
| `updated` | `datetime` |

### unified_identities

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `email` | `str` |
| `identity_type` | `str` |
| `num_users_linked` | `int` |
| `risk_score` | `float` |
| `created` | `datetime` |
| `updated` | `datetime` |

