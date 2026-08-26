# SnowflakeStorage

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `account` | `POSTURE_SNOWFLAKE_ACCOUNT` |
| `database` | `POSTURE_SNOWFLAKE_DATABASE` |
| `schema` | `POSTURE_SNOWFLAKE_SCHEMA` |
| `authenticator` | `POSTURE_SNOWFLAKE_AUTHENTICATOR` |

### Optional

| Config key | Environment variable |
| --- | --- |
| `user` | `POSTURE_SNOWFLAKE_USER` |
| `password` | `POSTURE_SNOWFLAKE_PASSWORD` |
| `role` | `POSTURE_SNOWFLAKE_ROLE` |
| `warehouse` | `POSTURE_SNOWFLAKE_WAREHOUSE` |
| `workload_identity_provider` | `POSTURE_SNOWFLAKE_WORKLOAD_IDENTITY_PROVIDER` |
| `private_key_file` | `POSTURE_SNOWFLAKE_PRIVATE_KEY_FILE` |
| `private_key_file_pwd` | `POSTURE_SNOWFLAKE_PRIVATE_KEY_FILE_PWD` |

## Example

```python
from posture import write_storage

write_storage(df, "snowflake", "table_name", config={ ... })
```

For a paginated collection, use `Storage()` and call `write_page()` once per page instead:

```python
from posture import Storage

store = Storage("snowflake", config={ ... })
for page in ccm.collect_page("table_name"):
    store.write_page(page, "table_name", mode="truncate")
```