# Tenable.io

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `access_key` | `TENABLEIO_ACCESS_KEY` |
| `secret_key` | `TENABLEIO_SECRET_KEY` |


## Example

```python
from posture import CCM

ccm = CCM("tenableio")  # credentials from TENABLEIO_ACCESS_KEY, TENABLEIO_SECRET_KEY
df = ccm.collect("assets")
df = ccm.collect("vulnerabilities")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("tenableio")  # credentials from TENABLEIO_ACCESS_KEY, TENABLEIO_SECRET_KEY

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [assets](#assets)
- [vulnerabilities](#vulnerabilities)

### assets

| Column | Type |
| --- | --- |
| `asset_id` | `str` |
| `hostname` | `str` |
| `fqdn` | `str` |
| `ipv4` | `str` |
| `ipv6` | `str` |
| `mac_address` | `str` |
| `operating_system` | `str` |
| `network_name` | `str` |
| `has_agent` | `bool` |
| `agent_uuid` | `str` |
| `first_seen` | `datetime` |
| `last_seen` | `datetime` |
| `sources` | `json` |

### vulnerabilities

| Column | Type |
| --- | --- |
| `asset_uuid` | `str` |
| `asset_hostname` | `str` |
| `asset_ipv4` | `str` |
| `asset_os` | `str` |
| `plugin_id` | `int` |
| `plugin_name` | `str` |
| `plugin_family` | `str` |
| `severity` | `str` |
| `severity_id` | `int` |
| `cvss_base_score` | `float` |
| `cvss3_base_score` | `float` |
| `cve` | `json` |
| `state` | `str` |
| `port` | `int` |
| `protocol` | `str` |
| `first_found` | `datetime` |
| `last_found` | `datetime` |

