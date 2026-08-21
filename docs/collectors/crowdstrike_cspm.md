# Crowdstrike Falcon Cloud Security (CSPM)

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `client_id` | `CROWDSTRIKE_CSPM_CLIENT_ID` |
| `client_secret` | `CROWDSTRIKE_CSPM_CLIENT_SECRET` |


## Example

```python
from posture import CCM

ccm = CCM("crowdstrike_cspm")  # credentials from CROWDSTRIKE_CSPM_CLIENT_ID, CROWDSTRIKE_CSPM_CLIENT_SECRET
df = ccm.collect("cloud_asset_inventory")
df = ccm.collect("cloud_risks")
df = ccm.collect("iom")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("crowdstrike_cspm")  # credentials from CROWDSTRIKE_CSPM_CLIENT_ID, CROWDSTRIKE_CSPM_CLIENT_SECRET

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [cloud_asset_inventory](#cloud_asset_inventory)
- [cloud_risks](#cloud_risks)
- [iom](#iom)

### cloud_asset_inventory

| Column | Type |
| --- | --- |
| `id` | `str` |
| `resource_id` | `str` |
| `resource_name` | `str` |
| `resource_type` | `str` |
| `cloud_provider` | `str` |
| `account_id` | `str` |
| `region` | `str` |
| `service` | `str` |
| `tags` | `json` |
| `first_seen` | `datetime` |
| `last_seen` | `datetime` |

### cloud_risks

| Column | Type |
| --- | --- |
| `id` | `str` |
| `cloud_provider` | `str` |
| `account_id` | `str` |
| `account_name` | `str` |
| `resource_id` | `str` |
| `resource_type` | `str` |
| `resource_gcrn` | `str` |
| `policy_id` | `str` |
| `risk_type` | `str` |
| `severity` | `str` |
| `status` | `str` |
| `description` | `str` |
| `first_seen` | `datetime` |
| `last_seen` | `datetime` |

### iom

| Column | Type |
| --- | --- |
| `id` | `str` |
| `cloud_provider` | `str` |
| `cloud_scope` | `str` |
| `account_id` | `str` |
| `account_name` | `str` |
| `resource_id` | `str` |
| `resource_type` | `str` |
| `resource_parent` | `str` |
| `resource_gcrn` | `str` |
| `policy_id` | `str` |
| `policy_name` | `str` |
| `rule_id` | `str` |
| `rule_name` | `str` |
| `severity` | `str` |
| `status` | `str` |
| `framework` | `str` |
| `benchmark_name` | `str` |
| `created_at` | `datetime` |
| `first_detected` | `datetime` |
| `last_detected` | `datetime` |

