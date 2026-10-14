# Qualys Policy Compliance

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `username` | `QUALYS_USERNAME` |
| `password` | `QUALYS_PASSWORD` |
| `base_url` | `QUALYS_BASE_URL` |


## Example

```python
from posture import CCM

ccm = CCM("qualys_compliance")  # credentials from QUALYS_USERNAME, QUALYS_PASSWORD, QUALYS_BASE_URL
df = ccm.collect("compliance_policies")
df = ccm.collect("compliance_policy_controls")
df = ccm.collect("compliance_posture")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("qualys_compliance")  # credentials from QUALYS_USERNAME, QUALYS_PASSWORD, QUALYS_BASE_URL

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [compliance_policies](#compliance_policies)
- [compliance_policy_controls](#compliance_policy_controls)
- [compliance_posture](#compliance_posture)

### compliance_policies

| Column | Type |
| --- | --- |
| `policy_id` | `str` |
| `title` | `str` |
| `status` | `str` |
| `is_locked` | `bool` |
| `evaluate_now` | `str` |
| `asset_group_ids` | `str` |
| `created` | `datetime` |
| `created_by` | `str` |
| `last_modified` | `datetime` |
| `last_modified_by` | `str` |
| `last_evaluated` | `datetime` |

### compliance_policy_controls

Derived from [`compliance_policies`](#compliance_policies) — no separate network call.

| Column | Type |
| --- | --- |
| `policy_id` | `str` |
| `policy_title` | `str` |
| `control_id` | `str` |
| `statement` | `str` |
| `criticality_label` | `str` |
| `criticality_value` | `int` |
| `status` | `str` |

### compliance_posture

| Column | Type |
| --- | --- |
| `posture_id` | `str` |
| `policy_id` | `str` |
| `host_id` | `str` |
| `control_id` | `str` |
| `technology_id` | `str` |
| `instance` | `str` |
| `status` | `str` |
| `previous_status` | `str` |
| `posture_modified_date` | `datetime` |
| `evaluation_date` | `datetime` |
| `first_fail_date` | `datetime` |
| `last_fail_date` | `datetime` |
| `first_pass_date` | `datetime` |
| `last_pass_date` | `datetime` |

