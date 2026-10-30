# Qualys

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `username` | `QUALYS_USERNAME` |
| `password` | `QUALYS_PASSWORD` |
| `base_url` | `QUALYS_BASE_URL` |

### Optional

| Config key | Environment variable |
| --- | --- |
| `gateway_url` | `QUALYS_GATEWAY_URL` |

## Example

```python
from posture import CCM

ccm = CCM("qualys")  # credentials from QUALYS_USERNAME, QUALYS_PASSWORD, QUALYS_BASE_URL
df = ccm.collect("assets")
df = ccm.collect("assets_open_ports")
df = ccm.collect("assets_software")
df = ccm.collect("compliance_policies")
df = ccm.collect("compliance_policy_controls")
df = ccm.collect("compliance_posture")
df = ccm.collect("vm_detections")
df = ccm.collect("vm_hosts")
df = ccm.collect("vm_knowledgebase")
df = ccm.collect("webapps")
df = ccm.collect("webapps_findings")
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

- [assets](#assets)
- [assets_open_ports](#assets_open_ports)
- [assets_software](#assets_software)
- [compliance_policies](#compliance_policies)
- [compliance_policy_controls](#compliance_policy_controls)
- [compliance_posture](#compliance_posture)
- [vm_detections](#vm_detections)
- [vm_hosts](#vm_hosts)
- [vm_knowledgebase](#vm_knowledgebase)
- [webapps](#webapps)
- [webapps_findings](#webapps_findings)

### assets

| Column | Type |
| --- | --- |
| `asset_id` | `str` |
| `asset_uuid` | `str` |
| `host_id` | `str` |
| `asset_name` | `str` |
| `asset_type` | `str` |
| `ip` | `str` |
| `dns_name` | `str` |
| `netbios_name` | `str` |
| `os_name` | `str` |
| `os_full_name` | `str` |
| `os_category` | `str` |
| `hardware_full_name` | `str` |
| `hardware_manufacturer` | `str` |
| `hardware_model` | `str` |
| `last_logged_on_user` | `str` |
| `last_boot` | `datetime` |
| `agent_version` | `str` |
| `agent_status` | `str` |
| `sensor_modules` | `json` |
| `last_vm_scan` | `datetime` |
| `last_full_scan` | `datetime` |
| `criticality_score` | `int` |
| `risk_score` | `int` |
| `tags` | `json` |
| `created` | `datetime` |
| `last_updated` | `datetime` |

### assets_open_ports

Derived from [`assets`](#assets) — no separate network call.

| Column | Type |
| --- | --- |
| `asset_id` | `str` |
| `host_id` | `str` |
| `asset_name` | `str` |
| `port` | `int` |
| `protocol` | `str` |
| `detected_service` | `str` |
| `first_found` | `datetime` |
| `last_updated` | `datetime` |

### assets_software

Derived from [`assets`](#assets) — no separate network call.

| Column | Type |
| --- | --- |
| `asset_id` | `str` |
| `host_id` | `str` |
| `asset_name` | `str` |
| `software_id` | `str` |
| `full_name` | `str` |
| `product` | `str` |
| `version` | `str` |
| `publisher` | `str` |
| `category` | `str` |

### compliance_policies

| Column | Type |
| --- | --- |
| `policy_id` | `str` |
| `title` | `str` |
| `status` | `str` |
| `is_locked` | `bool` |
| `evaluate_now` | `str` |
| `asset_group_ids` | `str` |
| `created` | `datetime` |
| `created_by` | `str` |
| `last_modified` | `datetime` |
| `last_modified_by` | `str` |
| `last_evaluated` | `datetime` |

### compliance_policy_controls

Derived from [`compliance_policies`](#compliance_policies) — no separate network call.

| Column | Type |
| --- | --- |
| `policy_id` | `str` |
| `policy_title` | `str` |
| `control_id` | `str` |
| `statement` | `str` |
| `criticality_label` | `str` |
| `criticality_value` | `int` |
| `status` | `str` |

### compliance_posture

| Column | Type |
| --- | --- |
| `posture_id` | `str` |
| `policy_id` | `str` |
| `host_id` | `str` |
| `control_id` | `str` |
| `technology_id` | `str` |
| `instance` | `str` |
| `status` | `str` |
| `previous_status` | `str` |
| `posture_modified` | `datetime` |
| `last_evaluated` | `datetime` |
| `first_failed` | `datetime` |
| `last_failed` | `datetime` |
| `first_passed` | `datetime` |
| `last_passed` | `datetime` |

### vm_detections

Derived from [`host_detections`](#host_detections) — no separate network call.

| Column | Type |
| --- | --- |
| `host_id` | `str` |
| `host_ip` | `str` |
| `host_dns_name` | `str` |
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

### vm_hosts

| Column | Type |
| --- | --- |
| `host_id` | `str` |
| `ip` | `str` |
| `ipv6` | `str` |
| `tracking_method` | `str` |
| `dns_name` | `str` |
| `netbios_name` | `str` |
| `os` | `str` |
| `qg_host_id` | `str` |
| `cloud_provider` | `str` |
| `cloud_service` | `str` |
| `cloud_resource_id` | `str` |
| `last_boot` | `datetime` |
| `last_vuln_scan` | `datetime` |
| `last_vm_scan` | `datetime` |
| `last_pc_scan` | `datetime` |
| `agent_version` | `str` |
| `agent_status` | `str` |
| `agent_last_checked_in` | `datetime` |
| `tags` | `json` |

### vm_knowledgebase

| Column | Type |
| --- | --- |
| `qid` | `str` |
| `vuln_type` | `str` |
| `severity` | `int` |
| `title` | `str` |
| `category` | `str` |
| `patchable` | `bool` |
| `pci_flag` | `bool` |
| `published` | `datetime` |
| `last_modified` | `datetime` |
| `cvss_base` | `float` |
| `cvss3_base` | `float` |
| `cve_list` | `json` |

### webapps

| Column | Type |
| --- | --- |
| `webapp_id` | `str` |
| `name` | `str` |
| `url` | `str` |
| `os` | `str` |
| `owner_username` | `str` |
| `scope` | `str` |
| `tags` | `json` |
| `is_scheduled` | `bool` |
| `is_scanned` | `bool` |
| `last_scan_id` | `str` |
| `created` | `datetime` |
| `last_updated` | `datetime` |

### webapps_findings

| Column | Type |
| --- | --- |
| `finding_id` | `str` |
| `unique_id` | `str` |
| `qid` | `str` |
| `title` | `str` |
| `type` | `str` |
| `finding_type` | `str` |
| `severity` | `int` |
| `status` | `str` |
| `url` | `str` |
| `potential` | `bool` |
| `detection_score` | `int` |
| `cvss3_base` | `float` |
| `cvss3_attack_vector` | `str` |
| `cwe` | `json` |
| `owasp` | `json` |
| `wasc` | `json` |
| `webapp_id` | `str` |
| `webapp_name` | `str` |
| `webapp_url` | `str` |
| `first_found` | `datetime` |
| `last_found` | `datetime` |
| `last_tested` | `datetime` |
| `times_detected` | `int` |
| `last_updated` | `datetime` |
| `is_ignored` | `bool` |
| `ignored_reason` | `str` |
| `ignored_date` | `datetime` |

