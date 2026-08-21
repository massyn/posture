# Cloudflare

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `api_token` | `CLOUDFLARE_API_TOKEN` |


## Example

```python
from posture import CCM

ccm = CCM("cloudflare")  # credentials from CLOUDFLARE_API_TOKEN
df = ccm.collect("cdn_protected_domains")
df = ccm.collect("dns_records")
df = ccm.collect("zones")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("cloudflare")  # credentials from CLOUDFLARE_API_TOKEN

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [cdn_protected_domains](#cdn_protected_domains)
- [dns_records](#dns_records)
- [zones](#zones)

### cdn_protected_domains

| Column | Type |
| --- | --- |
| `zone_id` | `str` |
| `zone_name` | `str` |
| `id` | `str` |
| `name` | `str` |
| `type` | `str` |
| `content` | `str` |
| `ttl` | `int` |
| `proxied` | `bool` |
| `created_on` | `datetime` |
| `modified_on` | `datetime` |

### dns_records

| Column | Type |
| --- | --- |
| `zone_id` | `str` |
| `zone_name` | `str` |
| `id` | `str` |
| `name` | `str` |
| `type` | `str` |
| `content` | `str` |
| `ttl` | `int` |
| `proxiable` | `bool` |
| `proxied` | `bool` |
| `locked` | `bool` |
| `comment` | `str` |
| `tags` | `json` |
| `created_on` | `datetime` |
| `modified_on` | `datetime` |

### zones

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `status` | `str` |
| `paused` | `bool` |
| `type` | `str` |
| `development_mode` | `int` |
| `name_servers` | `json` |
| `original_name_servers` | `json` |
| `account_id` | `str` |
| `account_name` | `str` |
| `plan_name` | `str` |
| `created_on` | `datetime` |
| `modified_on` | `datetime` |
| `activated_on` | `datetime` |

