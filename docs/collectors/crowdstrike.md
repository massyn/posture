# CrowdStrike

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `client_id` | `CROWDSTRIKE_CLIENT_ID` |
| `client_secret` | `CROWDSTRIKE_CLIENT_SECRET` |


## Example

```python
from posture import CCM

ccm = CCM("crowdstrike")  # credentials from CROWDSTRIKE_CLIENT_ID, CROWDSTRIKE_CLIENT_SECRET
df = ccm.collect("host_groups")
df = ccm.collect("hosts")
df = ccm.collect("vulnerabilities")
df = ccm.collect("vulnerability_remediations")
df = ccm.collect("zero_trust_assessment")
df = ccm.collect("zero_trust_assessment_os_signals")
df = ccm.collect("zero_trust_assessment_sensor_signals")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("crowdstrike")  # credentials from CROWDSTRIKE_CLIENT_ID, CROWDSTRIKE_CLIENT_SECRET

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [host_groups](#host_groups)
- [hosts](#hosts)
- [vulnerabilities](#vulnerabilities)
- [vulnerability_remediations](#vulnerability_remediations)
- [zero_trust_assessment](#zero_trust_assessment)
- [zero_trust_assessment_os_signals](#zero_trust_assessment_os_signals)
- [zero_trust_assessment_sensor_signals](#zero_trust_assessment_sensor_signals)

### host_groups

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `description` | `str` |
| `group_type` | `str` |
| `assignment_rule` | `str` |
| `created_by` | `str` |
| `created_at` | `datetime` |
| `modified_by` | `str` |
| `modified_at` | `datetime` |

### hosts

| Column | Type |
| --- | --- |
| `client_id` | `str` |
| `device_id` | `str` |
| `hostname` | `str` |
| `kernel_version` | `str` |
| `last_login_timestamp` | `datetime` |
| `local_ip` | `str` |
| `mac_address` | `str` |
| `last_login_uid` | `str` |
| `last_login_user` | `str` |
| `first_seen` | `datetime` |
| `last_seen` | `datetime` |
| `os_build` | `str` |
| `os_version` | `str` |
| `platform_name` | `str` |
| `provision_status` | `str` |
| `reduced_functionality_mode` | `bool` |
| `serial_number` | `str` |
| `host_status` | `str` |
| `system_manufacturer` | `str` |
| `system_product_name` | `str` |
| `cloud_provider` | `str` |
| `cloud_account_id` | `str` |
| `cloud_instance_id` | `str` |

### vulnerabilities

| Column | Type |
| --- | --- |
| `id` | `str` |
| `agent_id` | `str` |
| `client_id` | `str` |
| `status` | `str` |
| `cve_id` | `str` |
| `description` | `str` |
| `exprt_rating` | `str` |
| `remediation_level` | `str` |
| `severity` | `str` |
| `vector` | `str` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |
| `published_on` | `datetime` |
| `spotlight_published_at` | `datetime` |
| `is_cisa_kev` | `bool` |
| `is_suppressed` | `bool` |
| `exploit_status` | `int` |
| `exploitability_score` | `float` |
| `impact_score` | `float` |
| `base_score` | `float` |

### vulnerability_remediations

Derived from [`vulnerabilities`](#vulnerabilities) — no separate network call.

| Column | Type |
| --- | --- |
| `id` | `str` |
| `action` | `str` |
| `entity_id` | `str` |
| `link` | `str` |
| `reference` | `str` |
| `title` | `str` |
| `vendor_url` | `str` |

### zero_trust_assessment

| Column | Type |
| --- | --- |
| `aid` | `str` |
| `cid` | `str` |
| `system_serial_number` | `str` |
| `event_platform` | `str` |
| `product_type_desc` | `str` |
| `modified_time` | `datetime` |
| `sensor_file_status` | `str` |
| `assessment_sensor_config` | `int` |
| `assessment_overall` | `int` |
| `assessment_version` | `str` |

### zero_trust_assessment_os_signals

Derived from [`zero_trust_assessment`](#zero_trust_assessment) — no separate network call.

| Column | Type |
| --- | --- |
| `aid` | `str` |
| `type` | `str` |
| `criteria` | `str` |
| `group_name` | `str` |
| `meets_criteria` | `str` |
| `signal_id` | `str` |
| `signal_name` | `str` |

### zero_trust_assessment_sensor_signals

Derived from [`zero_trust_assessment`](#zero_trust_assessment) — no separate network call.

| Column | Type |
| --- | --- |
| `aid` | `str` |
| `type` | `str` |
| `criteria` | `str` |
| `group_name` | `str` |
| `meets_criteria` | `str` |
| `signal_id` | `str` |
| `signal_name` | `str` |

