# JsonStorage

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `path` | `POSTURE_JSON_PATH` |


## Example

```python
from posture import write_storage

write_storage(df, "json", "table_name", config={ ... })
```

For a paginated collection, use `open_storage()` and call `write_page()` once per page instead:

```python
from posture import open_storage

store = open_storage("json", config={ ... })
for page in ccm.collect_page("table_name"):
    store.write_page(page, "table_name", mode="truncate")
```