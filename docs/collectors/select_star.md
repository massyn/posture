# Select Star

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `token` | `SELECTSTAR_TOKEN` |

### Optional

| Config key | Environment variable |
| --- | --- |
| `endpoint` | `SELECTSTAR_ENDPOINT` |

## Example

```python
from posture import CCM

ccm = CCM("select_star")  # credentials from SELECTSTAR_TOKEN
df = ccm.collect("databases")
df = ccm.collect("tables")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("select_star")  # credentials from SELECTSTAR_TOKEN

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [databases](#databases)
- [tables](#tables)

### databases

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `native_type` | `str` |
| `description` | `str` |
| `url` | `str` |
| `table_count` | `int` |
| `tags` | `json` |
| `owners` | `json` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |

### tables

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `full_name` | `str` |
| `database_id` | `str` |
| `database_name` | `str` |
| `schema_name` | `str` |
| `table_type` | `str` |
| `description` | `str` |
| `url` | `str` |
| `row_count` | `int` |
| `column_count` | `int` |
| `tags` | `json` |
| `owners` | `json` |
| `popularity` | `float` |
| `last_refreshed_at` | `datetime` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |

