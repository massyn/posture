# MacAdmins SOFA Feed

[← back to index](../index.md)

## Environment variables

No required configuration.


## Example

```python
from posture import CCM

ccm = CCM("macadmins")  # credentials from the environment
df = ccm.collect("macos_cves")
df = ccm.collect("macos_releases")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("macadmins")  # credentials from the environment

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [macos_cves](#macos_cves)
- [macos_releases](#macos_releases)

### macos_cves

Derived from [`macos_releases`](#macos_releases) — no separate network call.

| Column | Type |
| --- | --- |
| `product_version` | `str` |
| `cve_id` | `str` |
| `exploited` | `bool` |

### macos_releases

| Column | Type |
| --- | --- |
| `os_version_name` | `str` |
| `product_version` | `str` |
| `build` | `str` |
| `release_date` | `datetime` |
| `release_type` | `str` |
| `security_info_url` | `str` |
| `days_since_previous_release` | `int` |
| `unique_cves_count` | `int` |
| `exploited_cve_count` | `int` |

