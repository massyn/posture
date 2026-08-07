# Wiz

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `client_id` | `WIZ_CLIENT_ID` |
| `client_secret` | `WIZ_CLIENT_SECRET` |
| `api_endpoint` | `WIZ_API_ENDPOINT` |

## Example

```python
from posture import CCM

ccm = CCM("wiz")  # credentials from WIZ_CLIENT_ID, WIZ_CLIENT_SECRET, WIZ_API_ENDPOINT
df = ccm.collect("cloud_security_issues")
df = ccm.collect("inventory")
df = ccm.collect("vulnerabilities")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("wiz")  # credentials from WIZ_CLIENT_ID, WIZ_CLIENT_SECRET, WIZ_API_ENDPOINT

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [cloud_security_issues](#cloud_security_issues)
- [inventory](#inventory)
- [vulnerabilities](#vulnerabilities)

### cloud_security_issues

| Column | Type |
| --- | --- |
| `id` | `str` |
| `status` | `str` |
| `severity` | `str` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |
| `due_at` | `datetime` |
| `resolved_at` | `datetime` |
| `resolution_reason` | `str` |
| `entity_id` | `str` |
| `entity_provider_unique_id` | `str` |
| `entity_name` | `str` |
| `entity_type` | `str` |
| `entity_properties` | `json` |

### inventory

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `type` | `str` |
| `subscription_id` | `str` |
| `subscription_external_id` | `str` |
| `graph_entity_id` | `str` |
| `graph_entity_name` | `str` |
| `graph_entity_type` | `str` |
| `properties` | `json` |

### vulnerabilities

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `description` | `str` |
| `cve_description` | `str` |
| `vendor_severity` | `str` |
| `score` | `float` |
| `exploitability_score` | `float` |
| `impact_score` | `float` |
| `has_exploit` | `bool` |
| `has_cisa_kev_exploit` | `bool` |
| `detection_method` | `str` |
| `status` | `str` |
| `fixed_version` | `str` |
| `first_detected_at` | `datetime` |
| `last_detected_at` | `datetime` |
| `asset_id` | `str` |
| `asset_external_id` | `str` |
| `asset_name` | `str` |
| `asset_type` | `str` |
| `asset_native_type` | `str` |
| `asset_region` | `str` |
| `asset_cloud_platform` | `str` |
| `asset_status` | `str` |
| `asset_provider_unique_id` | `str` |
| `asset_subscription_id` | `str` |
| `asset_subscription_external_id` | `str` |
| `asset_subscription_name` | `str` |

