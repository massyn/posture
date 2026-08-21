# Crowdstrike Falcon Identity Protection

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `client_id` | `CROWDSTRIKE_IDENTITY_CLIENT_ID` |
| `client_secret` | `CROWDSTRIKE_IDENTITY_CLIENT_SECRET` |


## Example

```python
from posture import CCM

ccm = CCM("crowdstrike_identity")  # credentials from CROWDSTRIKE_IDENTITY_CLIENT_ID, CROWDSTRIKE_IDENTITY_CLIENT_SECRET
df = ccm.collect("detections")
df = ccm.collect("entities")
df = ccm.collect("entity_risk_factors")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("crowdstrike_identity")  # credentials from CROWDSTRIKE_IDENTITY_CLIENT_ID, CROWDSTRIKE_IDENTITY_CLIENT_SECRET

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [detections](#detections)
- [entities](#entities)
- [entity_risk_factors](#entity_risk_factors)

### detections

| Column | Type |
| --- | --- |
| `id` | `str` |
| `composite_id` | `str` |
| `client_id` | `str` |
| `product` | `str` |
| `type` | `str` |
| `name` | `str` |
| `description` | `str` |
| `severity` | `int` |
| `severity_name` | `str` |
| `confidence` | `int` |
| `status` | `str` |
| `source_account_name` | `str` |
| `source_account_domain` | `str` |
| `source_endpoint_ip_address` | `str` |
| `target_account_name` | `str` |
| `tactic` | `str` |
| `technique` | `str` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |
| `start_time` | `datetime` |
| `end_time` | `datetime` |

### entities

| Column | Type |
| --- | --- |
| `entity_id` | `str` |
| `primary_display_name` | `str` |
| `secondary_display_name` | `str` |
| `type` | `str` |
| `risk_score` | `int` |
| `risk_score_severity` | `str` |
| `email_addresses` | `json` |
| `ip_addresses` | `json` |
| `accounts` | `json` |

### entity_risk_factors

Derived from [`entities`](#entities) — no separate network call.

| Column | Type |
| --- | --- |
| `entity_id` | `str` |
| `type` | `str` |
| `severity` | `str` |

