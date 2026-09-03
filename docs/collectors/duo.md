# Cisco Duo

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `api_hostname` | `DUO_API_HOSTNAME` |
| `integration_key` | `DUO_INTEGRATION_KEY` |
| `secret_key` | `DUO_SECRET_KEY` |


## Example

```python
from posture import CCM

ccm = CCM("duo")  # credentials from DUO_API_HOSTNAME, DUO_INTEGRATION_KEY, DUO_SECRET_KEY
df = ccm.collect("admins")
df = ccm.collect("endpoints")
df = ccm.collect("groups")
df = ccm.collect("integrations")
df = ccm.collect("phones")
df = ccm.collect("users")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("duo")  # credentials from DUO_API_HOSTNAME, DUO_INTEGRATION_KEY, DUO_SECRET_KEY

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [admins](#admins)
- [endpoints](#endpoints)
- [groups](#groups)
- [integrations](#integrations)
- [phones](#phones)
- [users](#users)

### admins

| Column | Type |
| --- | --- |
| `admin_id` | `str` |
| `name` | `str` |
| `email` | `str` |
| `phone` | `str` |
| `role` | `str` |
| `status` | `str` |
| `restricted_by_admin_units` | `bool` |
| `password_change_required` | `bool` |
| `last_login` | `datetime` |
| `created` | `datetime` |
| `admin_units` | `json` |

### endpoints

| Column | Type |
| --- | --- |
| `epkey` | `str` |
| `username` | `str` |
| `email` | `str` |
| `computer_name` | `str` |
| `model` | `str` |
| `type` | `str` |
| `os_family` | `str` |
| `os_version` | `str` |
| `os_build` | `str` |
| `device_identifier` | `str` |
| `device_udid` | `str` |
| `hardware_uuid` | `str` |
| `disk_encryption_status` | `str` |
| `firewall_status` | `str` |
| `password_status` | `str` |
| `trusted_endpoint` | `str` |
| `health_app_client_version` | `str` |
| `security_agents` | `json` |
| `browsers` | `json` |
| `last_updated` | `datetime` |

### groups

| Column | Type |
| --- | --- |
| `group_id` | `str` |
| `name` | `str` |
| `description` | `str` |
| `status` | `str` |
| `push_enabled` | `bool` |
| `sms_enabled` | `bool` |
| `voice_enabled` | `bool` |
| `mobile_otp_enabled` | `bool` |

### integrations

| Column | Type |
| --- | --- |
| `integration_key` | `str` |
| `name` | `str` |
| `type` | `str` |
| `enroll_policy` | `str` |
| `greeting` | `str` |
| `notes` | `str` |
| `trusted_device_days` | `int` |
| `self_service_allowed` | `bool` |
| `username_normalization_policy` | `str` |
| `networks_for_api_access` | `json` |
| `adminapi_admins` | `bool` |
| `adminapi_read_resource` | `bool` |
| `adminapi_write_resource` | `bool` |
| `adminapi_read_log` | `bool` |
| `adminapi_settings` | `bool` |

### phones

| Column | Type |
| --- | --- |
| `phone_id` | `str` |
| `number` | `str` |
| `extension` | `str` |
| `name` | `str` |
| `type` | `str` |
| `platform` | `str` |
| `model` | `str` |
| `activated` | `bool` |
| `sms_passcodes_sent` | `bool` |
| `last_seen` | `datetime` |
| `capabilities` | `json` |
| `users` | `json` |

### users

| Column | Type |
| --- | --- |
| `user_id` | `str` |
| `username` | `str` |
| `realname` | `str` |
| `email` | `str` |
| `status` | `str` |
| `first_name` | `str` |
| `last_name` | `str` |
| `is_enrolled` | `bool` |
| `created` | `datetime` |
| `last_login` | `datetime` |
| `last_directory_sync` | `datetime` |
| `notes` | `str` |
| `aliases` | `json` |
| `groups` | `json` |
| `phones` | `json` |
| `tokens` | `json` |
| `webauthncredentials` | `json` |

