# PostgresStorage

[← back to index](../index.md)

## Environment variables

No required configuration — check the class docstring for constraints
required/optional flags can't express (e.g. Postgres requires either "dsn"
or discrete host/dbname/user/password, but each key alone is optional).

### Optional

| Config key | Environment variable |
| --- | --- |
| `dsn` | `POSTURE_POSTGRES_DSN` |
| `host` | `POSTURE_POSTGRES_HOST` |
| `port` | `POSTURE_POSTGRES_PORT` |
| `dbname` | `POSTURE_POSTGRES_DBNAME` |
| `user` | `POSTURE_POSTGRES_USER` |
| `password` | `POSTURE_POSTGRES_PASSWORD` |

## Example

```python
from posture import write_storage

write_storage(df, "postgres", "table_name", config={ ... })
```

For a paginated collection, use `open_storage()` and call `write_page()` once per page instead:

```python
from posture import open_storage

store = open_storage("postgres", config={ ... })
for page in ccm.collect_page("table_name"):
    store.write_page(page, "table_name", mode="truncate")
```