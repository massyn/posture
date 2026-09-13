# Recorded Future

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `token` | `RECORDEDFUTURE_TOKEN` |


## Example

```python
from posture import CCM

ccm = CCM("recorded_future")  # credentials from RECORDEDFUTURE_TOKEN
df = ccm.collect("alert_hits")
df = ccm.collect("alerts")
df = ccm.collect("vulnerability_risklist")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("recorded_future")  # credentials from RECORDEDFUTURE_TOKEN

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [alert_hits](#alert_hits)
- [alerts](#alerts)
- [vulnerability_risklist](#vulnerability_risklist)

### alert_hits

Derived from [`alerts`](#alerts) — no separate network call.

| Column | Type |
| --- | --- |
| `alert_id` | `str` |
| `hit_id` | `str` |
| `entities` | `json` |
| `document_title` | `str` |
| `document_url` | `str` |
| `document_source_id` | `str` |
| `document_source_name` | `str` |
| `fragment` | `str` |

### alerts

| Column | Type |
| --- | --- |
| `id` | `str` |
| `title` | `str` |
| `type` | `str` |
| `rule_id` | `str` |
| `rule_name` | `str` |
| `rule_portal_url` | `str` |
| `status` | `str` |
| `status_in_portal` | `str` |
| `assignee` | `str` |
| `note` | `str` |
| `url_api` | `str` |
| `url_portal` | `str` |

### vulnerability_risklist

| Column | Type |
| --- | --- |
| `name` | `str` |
| `risk` | `int` |
| `risk_string` | `str` |
| `evidence_details` | `json` |

