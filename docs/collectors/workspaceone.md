# Workspace ONE

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `client_id` | `WORKSPACEONE_CLIENT_ID` |
| `client_secret` | `WORKSPACEONE_CLIENT_SECRET` |
| `api_server` | `WORKSPACEONE_API_SERVER` |

### Optional

| Config key | Environment variable |
| --- | --- |
| `token_url` | `WORKSPACEONE_TOKEN_URL` |

## Example

```python
from posture import CCM

ccm = CCM("workspaceone")  # credentials from WORKSPACEONE_CLIENT_ID, WORKSPACEONE_CLIENT_SECRET, WORKSPACEONE_API_SERVER
df = ccm.collect("computers")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("workspaceone")  # credentials from WORKSPACEONE_CLIENT_ID, WORKSPACEONE_CLIENT_SECRET, WORKSPACEONE_API_SERVER

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [computers](#computers)

### computers

| Column | Type |
| --- | --- |
| `device_id` | `str` |
| `uuid` | `str` |
| `udid` | `str` |
| `serial_number` | `str` |
| `mac_address` | `str` |
| `imei` | `str` |
| `asset_number` | `str` |
| `device_friendly_name` | `str` |
| `device_reported_name` | `str` |
| `platform_name` | `str` |
| `device_type` | `str` |
| `model_identifier` | `str` |
| `model` | `str` |
| `operating_system` | `str` |
| `os_build_version` | `str` |
| `last_seen` | `datetime` |
| `last_enrolled_on` | `datetime` |
| `enrollment_status` | `str` |
| `compliance_status` | `str` |
| `compromised_status` | `str` |
| `is_supervised` | `bool` |
| `ownership` | `str` |
| `organization_group_name` | `str` |
| `organization_group_uuid` | `str` |
| `enrollment_user_name` | `str` |
| `enrollment_user_uuid` | `str` |
| `enrollment_user_email` | `str` |
| `managed_by` | `str` |
| `time_zone` | `str` |

