# CyberArk Privileged Access Manager

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `base_url` | `CYBERARK_BASE_URL` |
| `username` | `CYBERARK_USERNAME` |
| `password` | `CYBERARK_PASSWORD` |

### Optional

| Config key | Environment variable |
| --- | --- |
| `identity_url` | `CYBERARK_IDENTITY_URL` |
| `logon_type` | `CYBERARK_LOGON_TYPE` |
| `ca_bundle` | `CYBERARK_CA_BUNDLE` |
| `insecure` | `CYBERARK_INSECURE` |

## Example

```python
from posture import CCM

ccm = CCM("cyberark")  # credentials from CYBERARK_BASE_URL, CYBERARK_USERNAME, CYBERARK_PASSWORD
df = ccm.collect("accounts")
df = ccm.collect("safe_members")
df = ccm.collect("safes")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("cyberark")  # credentials from CYBERARK_BASE_URL, CYBERARK_USERNAME, CYBERARK_PASSWORD

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [accounts](#accounts)
- [safe_members](#safe_members)
- [safes](#safes)

### accounts

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `address` | `str` |
| `user_name` | `str` |
| `platform_id` | `str` |
| `safe_name` | `str` |
| `secret_type` | `str` |
| `automatic_management_enabled` | `bool` |
| `manual_management_reason` | `str` |
| `management_status` | `str` |
| `last_modified` | `datetime` |
| `last_reconciled` | `datetime` |
| `last_verified` | `datetime` |
| `platform_account_properties` | `json` |
| `created` | `datetime` |

### safe_members

| Column | Type |
| --- | --- |
| `safe_url_id` | `str` |
| `safe_name` | `str` |
| `member_id` | `str` |
| `member_name` | `str` |
| `member_type` | `str` |
| `is_predefined_user` | `bool` |
| `is_read_only` | `bool` |
| `membership_expiration` | `datetime` |
| `use_accounts` | `bool` |
| `retrieve_accounts` | `bool` |
| `list_accounts` | `bool` |
| `manage_safe` | `bool` |
| `manage_safe_members` | `bool` |
| `access_without_confirmation` | `bool` |
| `permissions` | `json` |

### safes

| Column | Type |
| --- | --- |
| `safe_url_id` | `str` |
| `safe_name` | `str` |
| `safe_number` | `int` |
| `description` | `str` |
| `location` | `str` |
| `creator_name` | `str` |
| `managing_cpm` | `str` |
| `olac_enabled` | `bool` |
| `number_of_versions_retention` | `int` |
| `number_of_days_retention` | `int` |
| `auto_purge_enabled` | `bool` |
| `created` | `datetime` |
| `last_modified` | `datetime` |

