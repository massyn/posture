# ParquetStorage

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `path` | `POSTURE_PARQUET_PATH` |


## Example

```python
from posture import write_storage

write_storage(df, "parquet", "table_name", config={ ... })
```

For a paginated collection, use `Storage()` and call `write_page()` once per page instead:

```python
from posture import Storage

store = Storage("parquet", config={ ... })
for page in ccm.collect_page("table_name"):
    store.write_page(page, "table_name", mode="truncate")
```