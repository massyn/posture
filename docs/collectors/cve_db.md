# cve-db

[← back to index](../index.md)

## Environment variables

No required configuration.

### Optional

| Config key | Environment variable |
| --- | --- |
| `base_url` | `CVE_DB_BASE_URL` |

## Example

```python
from posture import CCM

ccm = CCM("cve_db")  # credentials from the environment
df = ccm.collect("cve_cpe")
df = ccm.collect("cve_summary")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("cve_db")  # credentials from the environment

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [cve_cpe](#cve_cpe)
- [cve_summary](#cve_summary)

### cve_cpe

| Column | Type |
| --- | --- |
| `cve_id` | `str` |
| `criteria` | `str` |
| `vendor` | `str` |
| `product` | `str` |
| `version` | `str` |
| `version_start_including` | `str` |
| `version_start_excluding` | `str` |
| `version_end_including` | `str` |
| `version_end_excluding` | `str` |
| `vulnerable` | `int` |

### cve_summary

| Column | Type |
| --- | --- |
| `cve_id` | `str` |
| `published` | `datetime` |
| `last_modified` | `datetime` |
| `vuln_status` | `str` |
| `is_app` | `int` |
| `is_os` | `int` |
| `is_hardware` | `int` |
| `product` | `str` |
| `cwe` | `str` |
| `cvss_version` | `str` |
| `base_score` | `float` |
| `base_severity` | `str` |
| `is_remote` | `int` |
| `is_adjacent` | `int` |
| `is_local` | `int` |
| `is_physical` | `int` |
| `requires_auth` | `int` |
| `requires_user_interaction` | `int` |
| `ssvc_exploitation` | `str` |
| `ssvc_automatable` | `str` |
| `has_patch_reference` | `int` |
| `cvss_vector` | `str` |
| `epss` | `float` |
| `epss_percentile` | `float` |
| `is_kev` | `int` |
| `kev_date_added` | `datetime` |

