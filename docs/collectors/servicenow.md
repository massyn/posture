# ServiceNow

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `instance` | `SERVICENOW_INSTANCE` |

### Optional

| Config key | Environment variable |
| --- | --- |
| `auth_type` | `SERVICENOW_AUTH_TYPE` |
| `client_id` | `SERVICENOW_CLIENT_ID` |
| `client_secret` | `SERVICENOW_CLIENT_SECRET` |
| `username` | `SERVICENOW_USERNAME` |
| `password` | `SERVICENOW_PASSWORD` |
| `schema_file` | `SERVICENOW_SCHEMA_FILE` |

## Example

```python
from posture import CCM

ccm = CCM("servicenow")  # credentials from SERVICENOW_INSTANCE
df = ccm.collect("cmdb_ci")
df = ccm.collect("cmdb_ci_service")
df = ccm.collect("cmdb_rel_ci")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("servicenow")  # credentials from SERVICENOW_INSTANCE

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [cmdb_ci](#cmdb_ci)
- [cmdb_ci_service](#cmdb_ci_service)
- [cmdb_rel_ci](#cmdb_rel_ci)

### cmdb_ci

| Column | Type |
| --- | --- |
| `sys_id` | `str` |
| `name` | `str` |
| `sys_class_name` | `str` |
| `operational_status` | `str` |
| `install_status` | `str` |
| `sys_created_on` | `datetime` |
| `sys_updated_on` | `datetime` |

### cmdb_ci_service

| Column | Type |
| --- | --- |
| `sys_id` | `str` |
| `name` | `str` |
| `operational_status` | `str` |
| `sys_updated_on` | `datetime` |

### cmdb_rel_ci

| Column | Type |
| --- | --- |
| `sys_id` | `str` |
| `parent` | `str` |
| `child` | `str` |
| `type` | `str` |

