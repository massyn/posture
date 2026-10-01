# Palo Alto Cortex Cloud

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `token` | `CORTEX_TOKEN` |
| `api_key_id` | `CORTEX_API_KEY_ID` |
| `endpoint` | `CORTEX_ENDPOINT` |

### Optional

| Config key | Environment variable |
| --- | --- |
| `snapshot_timeout` | `CORTEX_SNAPSHOT_TIMEOUT` |

## Example

```python
from posture import CCM

ccm = CCM("cortex_cloud")  # credentials from CORTEX_TOKEN, CORTEX_API_KEY_ID, CORTEX_ENDPOINT
df = ccm.collect("assets")
df = ccm.collect("issues")
df = ccm.collect("vulnerabilities")
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
- [vulnerabilities](#vulnerabilities)

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

### vulnerabilities

| Column | Type |
| --- | --- |
| `platform_id` | `str` |
| `asset_id` | `str` |
| `asset_name` | `str` |
| `asset_type` | `str` |
| `asset_type_class` | `str` |
| `asset_category` | `str` |
| `asset_group_ids` | `json` |
| `provider` | `str` |
| `cve_id` | `str` |
| `cve_description` | `str` |
| `cve_publish_date` | `datetime` |
| `published_date` | `datetime` |
| `cvss_score` | `float` |
| `cvss_severity` | `str` |
| `epss_score` | `float` |
| `cortex_vulnerability_risk_score` | `float` |
| `cve_risk_factors` | `json` |
| `has_kev` | `bool` |
| `exploitable` | `bool` |
| `exploit_level` | `str` |
| `fix_available` | `bool` |
| `fix_versions` | `json` |
| `fix_date` | `datetime` |
| `affected_software` | `str` |
| `internet_exposed` | `bool` |
| `ipv4_addresses` | `json` |
| `ipv6_addresses` | `json` |
| `operating_system` | `str` |
| `os_family` | `str` |
| `finding_sources` | `json` |
| `has_issue` | `bool` |
| `issue_id` | `str` |
| `remediation` | `str` |
| `package_in_use` | `bool` |
| `package_version` | `str` |
| `package_type` | `str` |
| `package_purl` | `str` |
| `origin_package_name` | `str` |
| `file_path` | `str` |
| `image_name` | `str` |
| `first_observed` | `datetime` |
| `last_observed` | `datetime` |

