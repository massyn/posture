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
df = ccm.collect("device_library_items")
df = ccm.collect("device_parameters")
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
- [device_library_items](#device_library_items)
- [device_parameters](#device_parameters)
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
| `platform` | `str` |
| `os_version` | `str` |
| `system_version` | `str` |
| `model` | `str` |
| `serial_number` | `str` |
| `udid` | `str` |
| `processor_name` | `str` |
| `memory` | `str` |
| `assigned_user_email` | `str` |
| `assigned_user_name` | `str` |
| `blueprint_name` | `str` |
| `blueprint_uuid` | `str` |
| `last_user` | `str` |
| `first_enrollment` | `datetime` |
| `last_enrollment` | `datetime` |
| `mdm_enabled` | `bool` |
| `is_supervised` | `bool` |
| `mdm_install_date` | `datetime` |
| `last_check_in` | `datetime` |
| `agent_installed` | `bool` |
| `agent_version` | `str` |
| `agent_last_check_in` | `datetime` |
| `filevault_enabled` | `bool` |
| `filevault_recovery_key_type` | `str` |
| `filevault_recovery_key_escrowed` | `bool` |
| `filevault_next_rotation` | `datetime` |
| `filevault_regen_required` | `bool` |
| `activation_lock_enabled` | `bool` |
| `user_activation_lock_enabled` | `bool` |
| `activation_lock_supported` | `bool` |
| `recovery_lock_enabled` | `bool` |
| `firmware_password_exists` | `bool` |
| `remote_desktop_enabled` | `bool` |
| `auto_enrolled` | `bool` |
| `local_hostname` | `str` |
| `mac_address` | `str` |
| `ip_address` | `str` |
| `public_ip` | `str` |

### device_library_items

| Column | Type |
| --- | --- |
| `device_id` | `str` |
| `library_item_row_id` | `str` |
| `item_id` | `str` |
| `name` | `str` |
| `type` | `str` |
| `status` | `str` |
| `rules_present` | `bool` |
| `reported_at` | `datetime` |
| `most_recent_action` | `datetime` |

### device_parameters

| Column | Type |
| --- | --- |
| `device_id` | `str` |
| `item_id` | `str` |
| `name` | `str` |
| `category` | `str` |
| `subcategory` | `str` |
| `status` | `str` |

### devices

| Column | Type |
| --- | --- |
| `device_id` | `str` |
| `device_name` | `str` |
| `model` | `str` |
| `platform` | `str` |
| `os_version` | `str` |
| `serial_number` | `str` |
| `udid` | `str` |
| `asset_tag` | `str` |
| `blueprint_id` | `str` |
| `blueprint_name` | `str` |
| `mdm_enabled` | `bool` |
| `agent_installed` | `bool` |
| `agent_version` | `str` |
| `is_missing` | `bool` |
| `is_removed` | `bool` |
| `lost_mode_status` | `str` |
| `first_enrollment` | `datetime` |
| `last_enrollment` | `datetime` |
| `last_check_in` | `datetime` |
| `user_email` | `str` |
| `user_name` | `str` |
| `user_id` | `str` |
| `tags` | `json` |

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

