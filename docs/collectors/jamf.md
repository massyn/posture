# Jamf

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `url` | `JAMF_URL` |
| `client_id` | `JAMF_CLIENT_ID` |
| `client_secret` | `JAMF_CLIENT_SECRET` |

## Example

```python
from posture import CCM

ccm = CCM("jamf")  # credentials from JAMF_URL, JAMF_CLIENT_ID, JAMF_CLIENT_SECRET
df = ccm.collect("buildings")
df = ccm.collect("categories")
df = ccm.collect("computers_inventory")
df = ccm.collect("computers_inventory_detail")
df = ccm.collect("departments")
df = ccm.collect("mobile_devices")
df = ccm.collect("policies")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("jamf")  # credentials from JAMF_URL, JAMF_CLIENT_ID, JAMF_CLIENT_SECRET

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [buildings](#buildings)
- [categories](#categories)
- [computers_inventory](#computers_inventory)
- [computers_inventory_detail](#computers_inventory_detail)
- [departments](#departments)
- [mobile_devices](#mobile_devices)
- [policies](#policies)

### buildings

| Column | Type |
| --- | --- |
| `building_id` | `str` |
| `building_name` | `str` |

### categories

| Column | Type |
| --- | --- |
| `category_id` | `str` |
| `category_name` | `str` |

### computers_inventory

| Column | Type |
| --- | --- |
| `computer_id` | `str` |
| `device_udid` | `str` |
| `serial_number` | `str` |
| `last_inventory_update_timestamp` | `datetime` |
| `os_version` | `str` |

### computers_inventory_detail

| Column | Type |
| --- | --- |
| `computer_inventory_detail_id` | `str` |
| `serial_number` | `str` |
| `device_udid` | `str` |
| `hostname` | `str` |
| `last_contact_time` | `datetime` |
| `user_email` | `str` |
| `operating_system_version` | `str` |
| `boot_partition_filevault2_state` | `str` |
| `sip_status` | `str` |
| `firewall_enabled` | `bool` |
| `auto_login_disabled` | `bool` |
| `gatekeeper_status` | `str` |
| `secure_boot_level` | `str` |

### departments

| Column | Type |
| --- | --- |
| `department_id` | `str` |
| `department_name` | `str` |

### mobile_devices

| Column | Type |
| --- | --- |
| `mobile_device_id` | `str` |
| `device_udid` | `str` |
| `serial_number` | `str` |
| `last_inventory_update_timestamp` | `datetime` |
| `os_version` | `str` |

### policies

| Column | Type |
| --- | --- |
| `policy_id` | `str` |
| `policy_name` | `str` |
| `is_enabled` | `bool` |

