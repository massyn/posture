# endoflife.date

[← back to index](../index.md)

## Environment variables

No required configuration.

### Optional

| Config key | Environment variable |
| --- | --- |
| `products` | `ENDOFLIFE_PRODUCTS` |

## Example

```python
from posture import CCM

ccm = CCM("endoflife")  # credentials from the environment
df = ccm.collect("cycles")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("endoflife")  # credentials from the environment

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [cycles](#cycles)

### cycles

| Column | Type |
| --- | --- |
| `product` | `str` |
| `product_label` | `str` |
| `cycle` | `str` |
| `label` | `str` |
| `codename` | `str` |
| `release_date` | `datetime` |
| `is_lts` | `bool` |
| `lts_from` | `datetime` |
| `is_eoas` | `bool` |
| `eoas_from` | `datetime` |
| `is_eol` | `bool` |
| `eol_from` | `datetime` |
| `is_eoes` | `bool` |
| `eoes_from` | `datetime` |
| `is_maintained` | `bool` |
| `latest_version` | `str` |
| `latest_date` | `datetime` |
| `latest_link` | `str` |
| `custom` | `json` |

