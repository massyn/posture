# SailPoint Identity Security Cloud

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `base_url` | `SAILPOINT_BASE_URL` |
| `client_id` | `SAILPOINT_CLIENT_ID` |
| `client_secret` | `SAILPOINT_CLIENT_SECRET` |


## Example

```python
from posture import CCM

ccm = CCM("sailpoint")  # credentials from SAILPOINT_BASE_URL, SAILPOINT_CLIENT_ID, SAILPOINT_CLIENT_SECRET
df = ccm.collect("access_profiles")
df = ccm.collect("accounts")
df = ccm.collect("identities")
df = ccm.collect("roles")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("sailpoint")  # credentials from SAILPOINT_BASE_URL, SAILPOINT_CLIENT_ID, SAILPOINT_CLIENT_SECRET

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [access_profiles](#access_profiles)
- [accounts](#accounts)
- [identities](#identities)
- [roles](#roles)

### access_profiles

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `description` | `str` |
| `created` | `datetime` |
| `modified` | `datetime` |
| `enabled` | `bool` |
| `requestable` | `bool` |
| `owner_id` | `str` |
| `owner_name` | `str` |
| `source_id` | `str` |
| `source_name` | `str` |

### accounts

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `native_identity` | `str` |
| `identity_id` | `str` |
| `source_id` | `str` |
| `created` | `datetime` |
| `modified` | `datetime` |
| `authoritative` | `bool` |
| `disabled` | `bool` |
| `locked` | `bool` |
| `system_account` | `bool` |
| `uncorrelated` | `bool` |
| `manually_correlated` | `bool` |
| `has_entitlements` | `bool` |

### identities

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `display_name` | `str` |
| `first_name` | `str` |
| `last_name` | `str` |
| `email` | `str` |
| `created` | `datetime` |
| `modified` | `datetime` |
| `synced` | `datetime` |
| `status` | `str` |
| `is_manager` | `bool` |
| `disabled` | `bool` |
| `locked` | `bool` |
| `identity_profile_id` | `str` |
| `identity_profile_name` | `str` |
| `lifecycle_state_id` | `str` |
| `lifecycle_state_name` | `str` |
| `manager_id` | `str` |
| `manager_name` | `str` |

### roles

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `description` | `str` |
| `created` | `datetime` |
| `modified` | `datetime` |
| `enabled` | `bool` |
| `requestable` | `bool` |
| `owner_id` | `str` |
| `owner_name` | `str` |

