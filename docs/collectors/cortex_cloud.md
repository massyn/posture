# Palo Alto Cortex Cloud

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `token` | `CORTEX_TOKEN` |
| `api_key_id` | `CORTEX_API_KEY_ID` |
| `endpoint` | `CORTEX_ENDPOINT` |

## Example

```python
from posture import CCM

ccm = CCM("cortex_cloud")  # credentials from CORTEX_TOKEN, CORTEX_API_KEY_ID, CORTEX_ENDPOINT
df = ccm.collect("assets")
df = ccm.collect("issues")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("cortex_cloud")  # credentials from CORTEX_TOKEN, CORTEX_API_KEY_ID, CORTEX_ENDPOINT

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [assets](#assets)
- [issues](#issues)

### assets

| Column | Type |
| --- | --- |
| `id` | `str` |
| `strong_id` | `str` |
| `name` | `str` |
| `provider` | `str` |
| `realm` | `str` |
| `type_id` | `str` |
| `type_name` | `str` |
| `type_class` | `str` |
| `type_category` | `str` |
| `is_resource` | `bool` |
| `cloud_region` | `str` |
| `cloud_account_id` | `str` |
| `cloud_account_name` | `str` |
| `group_ids` | `json` |
| `tags` | `json` |
| `first_observed` | `datetime` |
| `last_observed` | `datetime` |
| `is_inactive` | `bool` |
| `is_publicly_accessible` | `bool` |
| `has_sensitive_data` | `bool` |
| `critical_issues` | `int` |
| `issues_breakdown` | `json` |
| `critical_cases` | `int` |
| `cases_breakdown` | `json` |

### issues

| Column | Type |
| --- | --- |
| `id` | `int` |
| `external_id` | `str` |
| `name` | `str` |
| `description` | `str` |
| `domain` | `str` |
| `category` | `str` |
| `severity` | `str` |
| `type` | `str` |
| `detection_method` | `str` |
| `detection_rule_id` | `str` |
| `status_progress` | `str` |
| `status_resolution_reason` | `str` |
| `status_resolution_comment` | `str` |
| `observation_time` | `datetime` |
| `insert_time` | `datetime` |
| `last_update_timestamp` | `datetime` |
| `assigned_to` | `str` |
| `is_excluded` | `bool` |
| `is_starred` | `bool` |
| `is_excepted` | `bool` |
| `remediation` | `str` |
| `impact` | `str` |
| `extended_description` | `str` |
| `tags` | `json` |
| `asset_ids` | `json` |
| `asset_names` | `json` |
| `asset_types` | `json` |
| `asset_providers` | `json` |
| `asset_categories` | `json` |
| `asset_classes` | `json` |
| `asset_regions` | `json` |
| `asset_accounts` | `json` |
| `asset_group_ids` | `json` |
| `asset_group_names` | `json` |
| `case_ids` | `json` |

