# DNSimple

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `token` | `DNSIMPLE_TOKEN` |

### Optional

| Config key | Environment variable |
| --- | --- |
| `endpoint` | `DNSIMPLE_ENDPOINT` |

## Example

```python
from posture import CCM

ccm = CCM("dnsimple")  # credentials from DNSIMPLE_TOKEN
df = ccm.collect("domains")
df = ccm.collect("zone_records")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("dnsimple")  # credentials from DNSIMPLE_TOKEN

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [domains](#domains)
- [zone_records](#zone_records)

### domains

| Column | Type |
| --- | --- |
| `id` | `str` |
| `account_id` | `str` |
| `registrant_id` | `str` |
| `name` | `str` |
| `unicode_name` | `str` |
| `state` | `str` |
| `auto_renew` | `bool` |
| `private_whois` | `bool` |
| `expires_on` | `datetime` |
| `expires_at` | `datetime` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |

### zone_records

| Column | Type |
| --- | --- |
| `zone` | `str` |
| `id` | `str` |
| `zone_id` | `str` |
| `parent_id` | `str` |
| `name` | `str` |
| `content` | `str` |
| `type` | `str` |
| `ttl` | `int` |
| `priority` | `int` |
| `regions` | `str` |
| `system_record` | `bool` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |

