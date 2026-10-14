# Qualys TotalAppSec

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `username` | `QUALYS_TAS_USERNAME` |
| `password` | `QUALYS_TAS_PASSWORD` |
| `base_url` | `QUALYS_TAS_BASE_URL` |


## Example

```python
from posture import CCM

ccm = CCM("qualys_tas")  # credentials from QUALYS_TAS_USERNAME, QUALYS_TAS_PASSWORD, QUALYS_TAS_BASE_URL
df = ccm.collect("findings")
df = ccm.collect("webapps")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("qualys_tas")  # credentials from QUALYS_TAS_USERNAME, QUALYS_TAS_PASSWORD, QUALYS_TAS_BASE_URL

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [findings](#findings)
- [webapps](#webapps)

### findings

| Column | Type |
| --- | --- |
| `id` | `int` |
| `unique_id` | `str` |
| `qid` | `int` |
| `name` | `str` |
| `type` | `str` |
| `finding_type` | `str` |
| `severity` | `int` |
| `status` | `str` |
| `url` | `str` |
| `potential` | `bool` |
| `detection_score` | `int` |
| `cvss_v3_base` | `float` |
| `cvss_v3_attack_vector` | `str` |
| `cwe` | `json` |
| `owasp` | `json` |
| `wasc` | `json` |
| `webapp_id` | `int` |
| `webapp_name` | `str` |
| `webapp_url` | `str` |
| `first_detected_date` | `datetime` |
| `last_detected_date` | `datetime` |
| `last_tested_date` | `datetime` |
| `times_detected` | `int` |
| `updated_date` | `datetime` |
| `is_ignored` | `bool` |
| `ignored_reason` | `str` |
| `ignored_date` | `datetime` |

### webapps

| Column | Type |
| --- | --- |
| `id` | `int` |
| `name` | `str` |
| `url` | `str` |
| `os` | `str` |
| `owner_username` | `str` |
| `scope` | `str` |
| `tags` | `json` |
| `is_scheduled` | `bool` |
| `is_scanned` | `bool` |
| `last_scan_id` | `int` |
| `created_date` | `datetime` |
| `updated_date` | `datetime` |

