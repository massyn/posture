# EntraID

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `tenant_id` | `AZURE_TENANT_ID` |
| `client_id` | `AZURE_CLIENT_ID` |
| `client_secret` | `AZURE_CLIENT_SECRET` |


## Example

```python
from posture import CCM

ccm = CCM("azure_entra")  # credentials from AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
df = ccm.collect("audit_logs")
df = ccm.collect("signins")
df = ccm.collect("users")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("azure_entra")  # credentials from AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [audit_logs](#audit_logs)
- [signins](#signins)
- [users](#users)

### audit_logs

| Column | Type |
| --- | --- |
| `audit_log_id` | `str` |
| `activity_display_name` | `str` |
| `activity_date_time` | `datetime` |
| `user_principal_name` | `str` |
| `initiated_by_user` | `str` |
| `initiated_by_app` | `str` |

### signins

| Column | Type |
| --- | --- |
| `user_principal_name` | `str` |
| `created_date_time` | `datetime` |

### users

| Column | Type |
| --- | --- |
| `user_id` | `str` |
| `display_name` | `str` |
| `given_name` | `str` |
| `surname` | `str` |
| `user_principal_name` | `str` |
| `mail` | `str` |
| `mail_nickname` | `str` |
| `job_title` | `str` |
| `company_name` | `str` |
| `department` | `str` |
| `employee_id` | `str` |
| `employee_type` | `str` |
| `employee_hire_date` | `datetime` |
| `employee_org_data` | `json` |
| `mobile_phone` | `str` |
| `fax_number` | `str` |
| `business_phones` | `json` |
| `office_location` | `str` |
| `street_address` | `str` |
| `city` | `str` |
| `state` | `str` |
| `country` | `str` |
| `postal_code` | `str` |
| `usage_location` | `str` |
| `preferred_language` | `str` |
| `preferred_data_location` | `str` |
| `account_enabled` | `bool` |
| `user_type` | `str` |
| `creation_type` | `str` |
| `external_user_state` | `str` |
| `external_user_state_change_date_time` | `datetime` |
| `age_group` | `str` |
| `consent_provided_for_minor` | `str` |
| `legal_age_group_classification` | `str` |
| `is_resource_account` | `bool` |
| `is_management_restricted` | `bool` |
| `show_in_address_list` | `bool` |
| `created_date_time` | `datetime` |
| `last_password_change_date_time` | `datetime` |
| `sign_in_sessions_valid_from_date_time` | `datetime` |
| `password_policies` | `str` |
| `password_profile` | `json` |
| `identities` | `json` |
| `other_mails` | `json` |
| `im_addresses` | `json` |
| `proxy_addresses` | `json` |
| `authorization_info` | `json` |
| `custom_security_attributes` | `json` |
| `assigned_licenses` | `json` |
| `assigned_plans` | `json` |
| `license_assignment_states` | `json` |
| `on_premises_sync_enabled` | `bool` |
| `on_premises_last_sync_date_time` | `datetime` |
| `on_premises_immutable_id` | `str` |
| `on_premises_distinguished_name` | `str` |
| `on_premises_domain_name` | `str` |
| `on_premises_sam_account_name` | `str` |
| `on_premises_security_identifier` | `str` |
| `on_premises_user_principal_name` | `str` |
| `on_premises_extension_attributes` | `json` |
| `on_premises_provisioning_errors` | `json` |
| `security_identifier` | `str` |

