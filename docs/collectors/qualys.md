# Qualys

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `username` | `QUALYS_USERNAME` |
| `password` | `QUALYS_PASSWORD` |
| `base_url` | `QUALYS_BASE_URL` |


## Example

```python
from posture import CCM

ccm = CCM("qualys")  # credentials from QUALYS_USERNAME, QUALYS_PASSWORD, QUALYS_BASE_URL
df = ccm.collect("hosts")
df = ccm.collect("vulnerabilities")
df = ccm.collect("vulnerability_detections")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("qualys")  # credentials from QUALYS_USERNAME, QUALYS_PASSWORD, QUALYS_BASE_URL

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [hosts](#hosts)
- [vulnerabilities](#vulnerabilities)
- [vulnerability_detections](#vulnerability_detections)

### hosts

| Column | Type |
| --- | --- |
| `host_id` | `str` |
| `ip` | `str` |
| `ipv6` | `str` |
| `tracking_method` | `str` |
| `dns` | `str` |
| `netbios` | `str` |
| `operating_system` | `str` |
| `qg_host_id` | `str` |
| `cloud_provider` | `str` |
| `cloud_service` | `str` |
| `cloud_resource_id` | `str` |
| `last_boot` | `datetime` |
| `last_vuln_scan_datetime` | `datetime` |
| `last_vm_scanned_date` | `datetime` |
| `last_pc_scanned_date` | `datetime` |
| `agent_version` | `str` |
| `agent_status` | `str` |
| `agent_last_checked_in` | `datetime` |
| `tags` | `json` |

### vulnerabilities

| Column | Type |
| --- | --- |
| `qid` | `str` |
| `vuln_type` | `str` |
| `severity_level` | `int` |
| `title` | `str` |
| `category` | `str` |
| `patchable` | `bool` |
| `pci_flag` | `bool` |
| `published_datetime` | `datetime` |
| `last_modified_datetime` | `datetime` |
| `cvss_base` | `float` |
| `cvss3_base` | `float` |
| `cve_list` | `json` |

### vulnerability_detections

Derived from [`host_detections`](#host_detections) — no separate network call.

| Column | Type |
| --- | --- |
| `host_id` | `str` |
| `host_ip` | `str` |
| `host_dns` | `str` |
| `host_os` | `str` |
| `qid` | `str` |
| `detection_type` | `str` |
| `severity` | `int` |
| `port` | `int` |
| `protocol` | `str` |
| `results` | `str` |
| `status` | `str` |
| `first_found` | `datetime` |
| `last_found` | `datetime` |
| `last_tested` | `datetime` |
| `last_updated` | `datetime` |
| `is_ignored` | `bool` |
| `is_disabled` | `bool` |

