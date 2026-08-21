# Tenable.sc

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `endpoint` | `TENABLESC_ENDPOINT` |
| `access_key` | `TENABLESC_ACCESS_KEY` |
| `secret_key` | `TENABLESC_SECRET_KEY` |


## Example

```python
from posture import CCM

ccm = CCM("tenablesc")  # credentials from TENABLESC_ENDPOINT, TENABLESC_ACCESS_KEY, TENABLESC_SECRET_KEY
df = ccm.collect("asset_ips")
df = ccm.collect("assets")
df = ccm.collect("hosts")
df = ccm.collect("vulnerabilities")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("tenablesc")  # credentials from TENABLESC_ENDPOINT, TENABLESC_ACCESS_KEY, TENABLESC_SECRET_KEY

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [asset_ips](#asset_ips)
- [assets](#assets)
- [hosts](#hosts)
- [vulnerabilities](#vulnerabilities)

### asset_ips

| Column | Type |
| --- | --- |
| `asset_id` | `str` |
| `asset_name` | `str` |
| `repository_name` | `str` |
| `ip` | `str` |

### assets

| Column | Type |
| --- | --- |
| `id` | `str` |
| `uuid` | `str` |
| `name` | `str` |
| `description` | `str` |
| `type` | `str` |
| `status` | `str` |
| `created_time` | `datetime` |
| `modified_time` | `datetime` |
| `owner_id` | `str` |
| `owner_name` | `str` |
| `owner_group_id` | `str` |
| `owner_group_name` | `str` |
| `ip_count` | `int` |
| `target_group` | `json` |
| `groups` | `json` |
| `repositories` | `json` |
| `tags` | `str` |
| `creator_id` | `str` |
| `creator_name` | `str` |

### hosts

| Column | Type |
| --- | --- |
| `id` | `str` |
| `uuid` | `str` |
| `tenable_uuid` | `str` |
| `name` | `str` |
| `ip_address` | `str` |
| `os` | `str` |
| `first_seen` | `datetime` |
| `last_seen` | `datetime` |
| `mac_address` | `str` |
| `source` | `str` |
| `rep_id` | `str` |
| `net_bios` | `str` |
| `net_bios_workgroup` | `str` |
| `created_time` | `datetime` |
| `modified_time` | `datetime` |
| `acr` | `str` |
| `aes` | `str` |
| `repository_id` | `str` |
| `repository_name` | `str` |
| `repository_description` | `str` |

### vulnerabilities

| Column | Type |
| --- | --- |
| `plugin_id` | `str` |
| `plugin_name` | `str` |
| `severity` | `str` |
| `severity_id` | `int` |
| `ip` | `str` |
| `dns_name` | `str` |
| `mac_address` | `str` |
| `port` | `int` |
| `protocol` | `str` |
| `uuid` | `str` |
| `repository_id` | `str` |
| `repository_name` | `str` |
| `first_seen` | `datetime` |
| `last_seen` | `datetime` |
| `cve` | `json` |
| `cvss_base_score` | `float` |
| `cvss3_base_score` | `float` |
| `solution` | `str` |
| `synopsis` | `str` |
| `state` | `str` |

