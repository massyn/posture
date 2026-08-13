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
df = ccm.collect("policy_risk_summary")
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
- [policy_risk_summary](#policy_risk_summary)
- [posture_policies](#posture_policies)
- [unified_identities](#unified_identities)

### monitored_services

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `app_type` | `str` |
| `score` | `int` |
| `integration_connected` | `bool` |
| `has_errors` | `bool` |
| `has_warnings` | `bool` |
| `is_archived` | `bool` |
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
| `rule_id` | `str` |
| `rule_name` | `str` |
| `rule_posture_category` | `str` |
| `rule_service_specific_category` | `str` |
| `detected_at` | `datetime` |
| `resolved_at` | `datetime` |

### policies

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `description` | `str` |
| `policy_type` | `str` |
| `is_reference` | `bool` |
| `enabled` | `bool` |
| `created` | `datetime` |
| `updated` | `datetime` |

### policy_risk_summary

| Column | Type |
| --- | --- |
| `policy_id` | `str` |
| `policy_name` | `str` |
| `policy_type` | `str` |
| `monitored_service_ids` | `json` |
| `active` | `bool` |
| `open_issues_count` | `int` |
| `total_rules_count` | `int` |
| `risk_score` | `int` |
| `risk_informational_count` | `int` |
| `risk_low_count` | `int` |
| `risk_medium_count` | `int` |
| `risk_high_count` | `int` |
| `risk_critical_count` | `int` |
| `last_completed_scan` | `datetime` |
| `last_policy_assessment_status` | `str` |

### posture_policies

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `description` | `str` |
| `policy_type` | `str` |
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

