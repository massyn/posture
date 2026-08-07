# Okta

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `domain` | `OKTA_DOMAIN` |
| `token` | `OKTA_TOKEN` |

## Example

```python
from posture import CCM

ccm = CCM("okta")  # credentials from OKTA_DOMAIN, OKTA_TOKEN
df = ccm.collect("device_users")
df = ccm.collect("devices")
df = ccm.collect("users")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("okta")  # credentials from OKTA_DOMAIN, OKTA_TOKEN

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [device_users](#device_users)
- [devices](#devices)
- [users](#users)

### device_users

| Column | Type |
| --- | --- |
| `device_id` | `str` |
| `created` | `datetime` |
| `managementstatus` | `str` |
| `screenlocktype` | `str` |
| `user_id` | `str` |
| `user_status` | `str` |
| `user_displayname` | `str` |
| `user_profile_login` | `str` |
| `user_created` | `datetime` |

### devices

| Column | Type |
| --- | --- |
| `id` | `str` |
| `created` | `datetime` |
| `status` | `str` |
| `lastupdated` | `datetime` |
| `profile_displayname` | `str` |
| `profile_platform` | `str` |
| `profile_manufacturer` | `str` |
| `profile_model` | `str` |
| `profile_osversion` | `str` |
| `profile_registered` | `bool` |
| `profile_securehardwarepresent` | `bool` |
| `profile_authenticatorappkey` | `str` |
| `profile_serialnumber` | `str` |
| `profile_udid` | `str` |
| `profile_imei` | `str` |
| `profile_meid` | `str` |
| `profile_sid` | `str` |
| `profile_diskencryptiontype` | `str` |
| `profile_integrityjailbreak` | `bool` |
| `profile_tpmpublickeyhash` | `str` |
| `resourcetype` | `str` |
| `resourcedisplayname_value` | `str` |
| `resourcedisplayname_sensitive` | `bool` |
| `resourceid` | `str` |
| `resourcealternateid` | `str` |

### users

| Column | Type |
| --- | --- |
| `id` | `str` |
| `status` | `str` |
| `created` | `datetime` |
| `activated` | `datetime` |
| `status_changed` | `datetime` |
| `last_login` | `datetime` |
| `last_updated` | `datetime` |
| `password_changed` | `datetime` |
| `type_id` | `str` |
| `profile_login` | `str` |
| `profile_first_name` | `str` |
| `profile_last_name` | `str` |
| `profile_nick_name` | `str` |
| `profile_display_name` | `str` |
| `profile_email` | `str` |
| `profile_secondEmail` | `str` |
| `profile_url` | `str` |
| `profile_preferred_language` | `str` |
| `profile_user_type` | `str` |
| `profile_organization` | `str` |
| `profile_title` | `str` |
| `profile_division` | `str` |
| `profile_department` | `str` |
| `profile_cost_center` | `str` |
| `profile_employee_number` | `str` |
| `profile_mobile_phone` | `str` |
| `profile_primary_phone` | `str` |
| `profile_street_address` | `str` |
| `profile_city` | `str` |
| `profile_state` | `str` |
| `profile_zip_code` | `str` |
| `profile_country_code` | `str` |

