# SentinelOne

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `console_url` | `SENTINELONE_CONSOLE_URL` |
| `api_token` | `SENTINELONE_API_TOKEN` |


## Example

```python
from posture import CCM

ccm = CCM("sentinelone")  # credentials from SENTINELONE_CONSOLE_URL, SENTINELONE_API_TOKEN
df = ccm.collect("agents")
df = ccm.collect("alerts")
df = ccm.collect("groups")
df = ccm.collect("installed_applications")
df = ccm.collect("sites")
df = ccm.collect("threats")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("sentinelone")  # credentials from SENTINELONE_CONSOLE_URL, SENTINELONE_API_TOKEN

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [agents](#agents)
- [alerts](#alerts)
- [groups](#groups)
- [installed_applications](#installed_applications)
- [sites](#sites)
- [threats](#threats)

### agents

| Column | Type |
| --- | --- |
| `agent_id` | `str` |
| `uuid` | `str` |
| `computer_name` | `str` |
| `os_type` | `str` |
| `os_revision` | `str` |
| `agent_version` | `str` |
| `serial_number` | `str` |
| `external_ip` | `str` |
| `network_status` | `str` |
| `is_active` | `bool` |
| `is_decommissioned` | `bool` |
| `infected` | `bool` |
| `site_id` | `str` |
| `site_name` | `str` |
| `group_id` | `str` |
| `group_name` | `str` |
| `account_id` | `str` |
| `account_name` | `str` |
| `registered_at` | `datetime` |
| `last_active_date` | `datetime` |
| `updated_at` | `datetime` |

### alerts

| Column | Type |
| --- | --- |
| `alert_id` | `str` |
| `agent_uuid` | `str` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |

### groups

| Column | Type |
| --- | --- |
| `group_id` | `str` |
| `name` | `str` |
| `type` | `str` |
| `site_id` | `str` |
| `is_default` | `bool` |

### installed_applications

| Column | Type |
| --- | --- |
| `agent_uuid` | `str` |
| `agent_computer_name` | `str` |
| `name` | `str` |
| `version` | `str` |
| `publisher` | `str` |
| `size` | `int` |
| `installed_date` | `datetime` |

### sites

| Column | Type |
| --- | --- |
| `site_id` | `str` |
| `name` | `str` |
| `state` | `str` |
| `account_id` | `str` |
| `account_name` | `str` |
| `created_at` | `datetime` |

### threats

| Column | Type |
| --- | --- |
| `threat_id` | `str` |
| `classification` | `str` |
| `threat_name` | `str` |
| `incident_status` | `str` |
| `mitigation_status` | `str` |
| `confidence_level` | `str` |
| `file_path` | `str` |
| `file_size` | `int` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |
| `agent_uuid` | `str` |

