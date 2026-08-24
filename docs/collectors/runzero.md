# runZero

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `token` | `RUNZERO_TOKEN` |

### Optional

| Config key | Environment variable |
| --- | --- |
| `endpoint` | `RUNZERO_ENDPOINT` |

## Example

```python
from posture import CCM

ccm = CCM("runzero")  # credentials from RUNZERO_TOKEN
df = ccm.collect("assets")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("runzero")  # credentials from RUNZERO_TOKEN

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [assets](#assets)

### assets

| Column | Type |
| --- | --- |
| `id` | `str` |
| `org_id` | `str` |
| `site_id` | `str` |
| `site_name` | `str` |
| `name` | `str` |
| `first_seen` | `datetime` |
| `last_seen` | `datetime` |
| `alive` | `bool` |
| `addresses` | `json` |
| `addresses_extra` | `json` |
| `mac_addresses` | `json` |
| `mac_vendors` | `json` |
| `hostnames` | `json` |
| `domains` | `json` |
| `hw` | `str` |
| `hw_vendor` | `str` |
| `hw_product` | `str` |
| `hw_types` | `json` |
| `os` | `str` |
| `os_version` | `str` |
| `os_vendor` | `str` |
| `type` | `str` |
| `subtype` | `str` |
| `sources` | `json` |
| `tags` | `json` |
| `comments` | `str` |
| `detected_by` | `str` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |

