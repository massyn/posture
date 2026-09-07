# HTTP headers

[← back to index](../index.md)

## Environment variables

No required configuration.

### Optional

| Config key | Environment variable |
| --- | --- |
| `hosts` | `HTTP_HOSTS` |

## Example

```python
from posture import CCM

ccm = CCM("http")  # credentials from the environment
df = ccm.collect("headers")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("http")  # credentials from the environment

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [headers](#headers)

### headers

| Column | Type |
| --- | --- |
| `host` | `str` |
| `ok` | `bool` |
| `status_code` | `int` |
| `secure` | `bool` |
| `tls_error` | `str` |
| `error` | `str` |
| `duration_ms` | `int` |
| `header_name` | `str` |
| `header_value` | `str` |

