# Plerion

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `endpoint` | `PLERION_ENDPOINT` |
| `api_key` | `PLERION_API_KEY` |


## Example

```python
from posture import CCM

ccm = CCM("plerion")  # credentials from PLERION_ENDPOINT, PLERION_API_KEY
df = ccm.collect("assets")
df = ccm.collect("findings")
df = ccm.collect("vulnerabilities")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("plerion")  # credentials from PLERION_ENDPOINT, PLERION_API_KEY

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [assets](#assets)
- [findings](#findings)
- [vulnerabilities](#vulnerabilities)

### assets

| Column | Type |
| --- | --- |
| `id` | `str` |
| `integration_id` | `str` |
| `provider` | `str` |
| `provider_account_id` | `str` |
| `type` | `str` |
| `name` | `str` |
| `resource_type` | `str` |
| `resource_id` | `str` |
| `resource_name` | `str` |
| `full_resource_name` | `str` |
| `resource_url` | `str` |
| `region` | `str` |
| `service` | `str` |
| `operational_state` | `str` |
| `operating_system` | `str` |
| `platform` | `str` |
| `first_observed_at` | `datetime` |
| `last_observed_at` | `datetime` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |
| `last_scanned_at` | `datetime` |
| `is_publicly_exposed` | `bool` |
| `is_vulnerable` | `bool` |
| `has_kev` | `bool` |
| `has_exploit` | `bool` |
| `is_exploitable` | `bool` |
| `has_admin_privileges` | `bool` |
| `has_overly_permissive_privileges` | `bool` |
| `risk_score` | `float` |
| `vulnerability_score` | `float` |
| `number_of_critical_vulnerabilities` | `int` |
| `number_of_high_vulnerabilities` | `int` |
| `number_of_medium_vulnerabilities` | `int` |
| `number_of_low_vulnerabilities` | `int` |
| `number_of_critical_secrets` | `int` |
| `number_of_high_secrets` | `int` |
| `number_of_medium_secrets` | `int` |
| `number_of_low_secrets` | `int` |
| `tags` | `json` |
| `resource_tags` | `json` |

### findings

| Column | Type |
| --- | --- |
| `id` | `str` |
| `integration_id` | `str` |
| `provider` | `str` |
| `provider_account_id` | `str` |
| `asset_id` | `str` |
| `resource_type` | `str` |
| `resource_id` | `str` |
| `full_resource_name` | `str` |
| `resource_url` | `str` |
| `region` | `str` |
| `service` | `str` |
| `detection_id` | `str` |
| `status` | `str` |
| `message` | `str` |
| `severity_level` | `str` |
| `modified_severity_level` | `str` |
| `likelihood` | `str` |
| `impact` | `str` |
| `calculated_severity` | `str` |
| `is_exempted` | `bool` |
| `first_observed_at` | `datetime` |
| `last_observed_at` | `datetime` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |
| `sla_due_at` | `datetime` |
| `sla_warn_at` | `datetime` |
| `tags` | `json` |
| `resource_tags` | `json` |
| `parameters` | `json` |
| `attack_paths` | `json` |

### vulnerabilities

| Column | Type |
| --- | --- |
| `asset_id` | `str` |
| `integration_id` | `str` |
| `provider` | `str` |
| `asset_type` | `str` |
| `vulnerability_id` | `str` |
| `title` | `str` |
| `description` | `str` |
| `severity_level` | `str` |
| `severity_level_value` | `int` |
| `severity_source` | `str` |
| `target_name` | `str` |
| `primary_url` | `str` |
| `has_kev` | `bool` |
| `has_exploit` | `bool` |
| `has_vendor_fix` | `bool` |
| `first_observed_at` | `datetime` |
| `last_observed_at` | `datetime` |
| `published_date` | `datetime` |
| `packages` | `json` |
| `cwes` | `json` |
| `known_exploit` | `json` |
| `exploits` | `json` |
| `exemptions` | `json` |

