# Microsoft Defender for Endpoint

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `tenant_id` | `MDE_TENANT_ID` |
| `client_id` | `MDE_CLIENT_ID` |
| `client_secret` | `MDE_CLIENT_SECRET` |


## Example

```python
from posture import CCM

ccm = CCM("mde")  # credentials from MDE_TENANT_ID, MDE_CLIENT_ID, MDE_CLIENT_SECRET
df = ccm.collect("device_av_info")
df = ccm.collect("machine_vulnerabilities")
df = ccm.collect("machines")
df = ccm.collect("vulnerabilities")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("mde")  # credentials from MDE_TENANT_ID, MDE_CLIENT_ID, MDE_CLIENT_SECRET

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [device_av_info](#device_av_info)
- [machine_vulnerabilities](#machine_vulnerabilities)
- [machines](#machines)
- [vulnerabilities](#vulnerabilities)

### device_av_info

| Column | Type |
| --- | --- |
| `machine_id` | `str` |
| `device_name` | `str` |
| `os_kind` | `str` |
| `os_platform` | `str` |
| `os_version` | `str` |
| `av_mode` | `str` |
| `av_signature_version` | `str` |
| `av_engine_version` | `str` |
| `av_platform_version` | `str` |
| `last_seen_time` | `datetime` |
| `quick_scan_result` | `str` |
| `quick_scan_error` | `str` |
| `quick_scan_time` | `datetime` |
| `full_scan_result` | `str` |
| `full_scan_error` | `str` |
| `full_scan_time` | `datetime` |
| `data_refresh_timestamp` | `datetime` |
| `av_engine_update_time` | `datetime` |
| `av_signature_update_time` | `datetime` |
| `av_platform_update_time` | `datetime` |
| `av_is_signature_up_to_date` | `bool` |
| `av_is_engine_up_to_date` | `bool` |
| `av_is_platform_up_to_date` | `bool` |
| `av_signature_publish_time` | `datetime` |
| `av_signature_data_refresh_time` | `datetime` |
| `cloud_protection_state` | `str` |
| `av_mode_data_refresh_time` | `datetime` |
| `rbac_group_name` | `str` |
| `rbac_group_id` | `str` |

### machine_vulnerabilities

| Column | Type |
| --- | --- |
| `machine_vulnerability_id` | `str` |
| `machine_id` | `str` |
| `device_name` | `str` |
| `cve_id` | `str` |
| `cvss_score` | `float` |
| `vulnerability_severity_level` | `str` |
| `exploitability_level` | `str` |
| `product_vendor` | `str` |
| `product_name` | `str` |
| `product_version` | `str` |
| `os_platform` | `str` |
| `rbac_group_name` | `str` |
| `rbac_group_id` | `str` |
| `recommended_security_update` | `str` |
| `recommended_security_update_id` | `str` |
| `security_update_available` | `bool` |
| `disk_paths` | `json` |
| `registry_paths` | `json` |
| `first_seen_timestamp` | `datetime` |
| `last_seen_timestamp` | `datetime` |

### machines

| Column | Type |
| --- | --- |
| `machine_id` | `str` |
| `device_name` | `str` |
| `os_platform` | `str` |
| `os_version` | `str` |
| `os_build` | `str` |
| `last_ip_address` | `str` |
| `last_external_ip_address` | `str` |
| `agent_version` | `str` |
| `health_status` | `str` |
| `risk_score` | `str` |
| `exposure_level` | `str` |
| `last_seen` | `datetime` |
| `first_seen` | `datetime` |
| `rbac_group_name` | `str` |
| `rbac_group_id` | `str` |
| `aad_device_id` | `str` |
| `device_value` | `str` |
| `is_aad_joined` | `bool` |
| `onboarding_status` | `str` |
| `managed_by` | `str` |

### vulnerabilities

| Column | Type |
| --- | --- |
| `vulnerability_id` | `str` |
| `vulnerability_name` | `str` |
| `description` | `str` |
| `severity` | `str` |
| `cvss_score` | `float` |
| `cvss_vector` | `str` |
| `exposed_machines` | `int` |
| `published_on` | `datetime` |
| `updated_on` | `datetime` |
| `first_detected` | `datetime` |
| `patch_first_available` | `datetime` |
| `public_exploit` | `bool` |
| `exploit_verified` | `bool` |
| `exploit_in_kit` | `bool` |
| `epss` | `float` |
| `status` | `str` |

