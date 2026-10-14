# Qualys Global AssetView

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `username` | `QUALYS_GAV_USERNAME` |
| `password` | `QUALYS_GAV_PASSWORD` |
| `gateway_url` | `QUALYS_GAV_GATEWAY_URL` |


## Example

```python
from posture import CCM

ccm = CCM("qualys_gav")  # credentials from QUALYS_GAV_USERNAME, QUALYS_GAV_PASSWORD, QUALYS_GAV_GATEWAY_URL
df = ccm.collect("asset_open_ports")
df = ccm.collect("asset_software")
df = ccm.collect("assets")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("qualys_gav")  # credentials from QUALYS_GAV_USERNAME, QUALYS_GAV_PASSWORD, QUALYS_GAV_GATEWAY_URL

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [asset_open_ports](#asset_open_ports)
- [asset_software](#asset_software)
- [assets](#assets)

### asset_open_ports

Derived from [`assets`](#assets) — no separate network call.

| Column | Type |
| --- | --- |
| `asset_id` | `str` |
| `host_id` | `str` |
| `asset_name` | `str` |
| `port` | `int` |
| `protocol` | `str` |
| `detected_service` | `str` |
| `first_found` | `datetime` |
| `last_updated` | `datetime` |

### asset_software

Derived from [`assets`](#assets) — no separate network call.

| Column | Type |
| --- | --- |
| `asset_id` | `str` |
| `host_id` | `str` |
| `asset_name` | `str` |
| `software_id` | `str` |
| `full_name` | `str` |
| `product` | `str` |
| `version` | `str` |
| `publisher` | `str` |
| `category` | `str` |

### assets

| Column | Type |
| --- | --- |
| `asset_id` | `str` |
| `asset_uuid` | `str` |
| `host_id` | `str` |
| `asset_name` | `str` |
| `asset_type` | `str` |
| `address` | `str` |
| `dns_name` | `str` |
| `netbios_name` | `str` |
| `os_name` | `str` |
| `os_full_name` | `str` |
| `os_category` | `str` |
| `hardware_full_name` | `str` |
| `hardware_manufacturer` | `str` |
| `hardware_model` | `str` |
| `last_logged_on_user` | `str` |
| `last_boot` | `datetime` |
| `agent_version` | `str` |
| `agent_status` | `str` |
| `sensor_modules` | `json` |
| `last_vm_scan` | `datetime` |
| `last_full_scan` | `datetime` |
| `criticality_score` | `int` |
| `risk_score` | `int` |
| `tags` | `json` |
| `created` | `datetime` |
| `last_updated` | `datetime` |

