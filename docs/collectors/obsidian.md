# Obsidian Security

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `token` | `OBSIDIAN_TOKEN` |

### Optional

| Config key | Environment variable |
| --- | --- |
| `endpoint` | `OBSIDIAN_ENDPOINT` |

## Example

```python
from posture import CCM

ccm = CCM("obsidian")  # credentials from OBSIDIAN_TOKEN
df = ccm.collect("posture_rule_tenant_states")
df = ccm.collect("posture_rules")
df = ccm.collect("posture_scores")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("obsidian")  # credentials from OBSIDIAN_TOKEN

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [posture_rule_tenant_states](#posture_rule_tenant_states)
- [posture_rules](#posture_rules)
- [posture_scores](#posture_scores)

### posture_rule_tenant_states

Derived from [`posture_rules`](#posture_rules) — no separate network call.

| Column | Type |
| --- | --- |
| `rule_id` | `str` |
| `tenant_id` | `str` |
| `is_passing` | `bool` |
| `violations` | `int` |
| `tenant_name` | `str` |
| `tenant_service_id` | `str` |
| `tenant_is_production` | `bool` |
| `tenant_sensitivity` | `str` |
| `tenant_platform` | `str` |
| `last_scanned` | `datetime` |
| `risk_accepted` | `bool` |
| `exceptions_count_active` | `int` |
| `exceptions_count_inactive` | `int` |
| `correction_score_change` | `float` |

### posture_rules

| Column | Type |
| --- | --- |
| `rule_id` | `str` |
| `platform_id` | `str` |
| `product_ids` | `json` |
| `security_domain_id` | `str` |
| `security_domain_name` | `str` |
| `name` | `str` |
| `risk_level` | `str` |
| `default_risk_level` | `str` |
| `standard_ids` | `json` |
| `control_ids` | `json` |
| `obsidian_rule` | `bool` |
| `release_label` | `str` |
| `benchmark_value_type` | `str` |
| `rule_value_type` | `str` |
| `description` | `str` |
| `remediation_instructions` | `str` |
| `exceptions_count_active` | `int` |
| `exceptions_count_inactive` | `int` |
| `total_violations` | `int` |
| `correction_score_change` | `float` |

### posture_scores

| Column | Type |
| --- | --- |
| `group_by` | `str` |
| `key` | `str` |
| `start_datetime` | `datetime` |
| `end_datetime` | `datetime` |
| `score_data` | `json` |

