# Microsoft Intune

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `tenant_id` | `INTUNE_TENANT_ID` |
| `client_id` | `INTUNE_CLIENT_ID` |
| `client_secret` | `INTUNE_CLIENT_SECRET` |

## Example

```python
from posture import CCM

ccm = CCM("intune")  # credentials from INTUNE_TENANT_ID, INTUNE_CLIENT_ID, INTUNE_CLIENT_SECRET
df = ccm.collect("attack_simulation_users")
df = ccm.collect("attack_simulations")
df = ccm.collect("device_compliance_policies")
df = ccm.collect("device_configuration_detail")
df = ccm.collect("device_configurations")
df = ccm.collect("managed_device_detail")
df = ccm.collect("managed_devices")
df = ccm.collect("users")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("intune")  # credentials from INTUNE_TENANT_ID, INTUNE_CLIENT_ID, INTUNE_CLIENT_SECRET

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [attack_simulation_users](#attack_simulation_users)
- [attack_simulations](#attack_simulations)
- [device_compliance_policies](#device_compliance_policies)
- [device_configuration_detail](#device_configuration_detail)
- [device_configurations](#device_configurations)
- [managed_device_detail](#managed_device_detail)
- [managed_devices](#managed_devices)
- [users](#users)

### attack_simulation_users

| Column | Type |
| --- | --- |
| `simulation_id` | `str` |
| `user_id` | `str` |
| `display_name` | `str` |
| `email` | `str` |
| `is_compromised` | `bool` |
| `compromised_date_time` | `datetime` |
| `assigned_trainings_count` | `int` |
| `completed_trainings_count` | `int` |
| `in_progress_trainings_count` | `int` |
| `reported_phish_date_time` | `datetime` |
| `simulation_events_json` | `json` |
| `training_events_json` | `json` |

### attack_simulations

| Column | Type |
| --- | --- |
| `simulation_id` | `str` |
| `display_name` | `str` |
| `description` | `str` |
| `attack_type` | `str` |
| `payload_delivery_platform` | `str` |
| `attack_technique` | `str` |
| `status` | `str` |
| `created_date_time` | `datetime` |
| `last_modified_date_time` | `datetime` |
| `launch_date_time` | `datetime` |
| `completion_date_time` | `datetime` |
| `is_automated` | `bool` |
| `automation_id` | `str` |
| `duration_in_days` | `int` |
| `training_setting_json` | `json` |
| `oauth_consent_app_detail_json` | `json` |
| `end_user_notification_setting_json` | `json` |
| `included_account_target_json` | `json` |
| `excluded_account_target_json` | `json` |
| `created_by_email` | `str` |
| `created_by_id` | `str` |
| `created_by_display_name` | `str` |
| `last_modified_by_email` | `str` |
| `last_modified_by_id` | `str` |
| `last_modified_by_display_name` | `str` |

### device_compliance_policies

| Column | Type |
| --- | --- |
| `policy_id` | `str` |
| `display_name` | `str` |
| `created_date_time` | `datetime` |
| `last_modified_date_time` | `datetime` |

### device_configuration_detail

| Column | Type |
| --- | --- |
| `configuration_id` | `str` |
| `display_name` | `str` |
| `description` | `str` |
| `created_date_time` | `datetime` |
| `last_modified_date_time` | `datetime` |
| `platforms` | `str` |
| `technologies` | `str` |
| `role_scope_tag_ids` | `json` |
| `settings_json` | `json` |
| `assignments_json` | `json` |

### device_configurations

| Column | Type |
| --- | --- |
| `configuration_id` | `str` |
| `display_name` | `str` |
| `description` | `str` |
| `created_date_time` | `datetime` |
| `last_modified_date_time` | `datetime` |
| `platforms` | `str` |
| `technologies` | `str` |
| `role_scope_tag_ids` | `json` |
| `settings_json` | `json` |
| `assignments_json` | `json` |

### managed_device_detail

| Column | Type |
| --- | --- |
| `device_id` | `str` |
| `device_name` | `str` |
| `operating_system` | `str` |
| `os_version` | `str` |
| `is_encrypted` | `bool` |
| `compliance_state` | `str` |
| `last_sync_datetime` | `datetime` |
| `user_principal_name` | `str` |
| `os_build_number` | `str` |
| `device_guard_vbs_state` | `str` |
| `device_guard_credential_guard_state` | `str` |
| `windows_active_malware_count` | `int` |

### managed_devices

| Column | Type |
| --- | --- |
| `device_id` | `str` |
| `device_name` | `str` |
| `operating_system` | `str` |
| `os_version` | `str` |
| `is_encrypted` | `bool` |
| `compliance_state` | `str` |
| `last_sync_datetime` | `datetime` |
| `user_principal_name` | `str` |

### users

| Column | Type |
| --- | --- |
| `user_id` | `str` |
| `display_name` | `str` |
| `given_name` | `str` |
| `surname` | `str` |
| `user_principal_name` | `str` |
| `mail` | `str` |
| `business_phones` | `json` |
| `mobile_phone` | `str` |
| `office_location` | `str` |
| `preferred_language` | `str` |
| `job_title` | `str` |
| `account_enabled` | `bool` |
| `created_date_time` | `datetime` |
| `department` | `str` |
| `company_name` | `str` |

