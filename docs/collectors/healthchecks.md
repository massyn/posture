# Healthchecks.io

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `token` | `HEALTHCHECKS_TOKEN` |

### Optional

| Config key | Environment variable |
| --- | --- |
| `api_url` | `HEALTHCHECKS_API_URL` |

## Example

```python
from posture import CCM

ccm = CCM("healthchecks")  # credentials from HEALTHCHECKS_TOKEN
df = ccm.collect("checks")
df = ccm.collect("flips")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("healthchecks")  # credentials from HEALTHCHECKS_TOKEN

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [checks](#checks)
- [flips](#flips)

### checks

| Column | Type |
| --- | --- |
| `name` | `str` |
| `slug` | `str` |
| `tags` | `str` |
| `desc` | `str` |
| `status` | `str` |
| `grace` | `int` |
| `timeout` | `int` |
| `schedule` | `str` |
| `tz` | `str` |
| `n_pings` | `int` |
| `started` | `bool` |
| `last_ping` | `datetime` |
| `next_ping` | `datetime` |
| `last_duration` | `int` |
| `manual_resume` | `bool` |
| `methods` | `str` |
| `subject` | `str` |
| `subject_fail` | `str` |
| `start_kw` | `str` |
| `success_kw` | `str` |
| `failure_kw` | `str` |
| `filter_subject` | `bool` |
| `filter_body` | `bool` |
| `filter_http_body` | `bool` |
| `filter_default_fail` | `bool` |
| `badge_url` | `str` |
| `channels` | `str` |
| `uuid` | `str` |
| `unique_key` | `str` |

### flips

| Column | Type |
| --- | --- |
| `check_key` | `str` |
| `check_name` | `str` |
| `timestamp` | `datetime` |
| `up` | `int` |

