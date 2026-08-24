# Kandji

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `api_url` | `KANDJI_API_URL` |
| `api_token` | `KANDJI_API_TOKEN` |


## Example

```python
from posture import CCM

ccm = CCM("kandji")  # credentials from KANDJI_API_URL, KANDJI_API_TOKEN
df = ccm.collect("blueprints")
df = ccm.collect("device_details")
df = ccm.collect("devices")
df = ccm.collect("vulnerabilities")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("kandji")  # credentials from KANDJI_API_URL, KANDJI_API_TOKEN

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [blueprints](#blueprints)
- [device_details](#device_details)
- [devices](#devices)
- [vulnerabilities](#vulnerabilities)

### blueprints

| Column | Type |
| --- | --- |
| `blueprint_id` | `str` |
| `name` | `str` |

### device_details

| Column | Type |
| --- | --- |
| `device_id` | `str` |
| `device_name` | `str` |
| `serial_number` | `str` |
| `platform` | `str` |
| `os_version` | `str` |
| `last_check_in` | `datetime` |
| `is_supervised` | `bool` |
| `filevault_enabled` | `bool` |
| `filevault_recovery_key_escrowed` | `bool` |
| `firewall_enabled` | `bool` |
| `gatekeeper_enabled` | `bool` |
| `sip_enabled` | `bool` |

### devices

| Column | Type |
| --- | --- |
| `device_id` | `str` |
| `device_name` | `str` |
| `model` | `str` |
| `platform` | `str` |
| `os_version` | `str` |
| `serial_number` | `str` |
| `asset_tag` | `str` |
| `blueprint_id` | `str` |
| `mdm_enabled` | `bool` |
| `agent_installed` | `bool` |
| `agent_version` | `str` |
| `is_missing` | `bool` |
| `is_removed` | `bool` |
| `first_enrollment` | `datetime` |
| `last_enrollment` | `datetime` |
| `last_check_in` | `datetime` |
| `user_email` | `str` |

### vulnerabilities

| Column | Type |
| --- | --- |
| `vulnerability_id` | `str` |
| `cve_id` | `str` |
| `device_id` | `str` |
| `severity` | `str` |
| `cvss_score` | `float` |
| `status` | `str` |
| `description` | `str` |
| `published_date` | `datetime` |
| `detected_date` | `datetime` |

