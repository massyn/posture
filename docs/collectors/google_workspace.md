# Google Workspace

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `service_account_json_path` | `GOOGLE_WORKSPACE_SERVICE_ACCOUNT_JSON_PATH` |
| `admin_email` | `GOOGLE_WORKSPACE_ADMIN_EMAIL` |

### Optional

| Config key | Environment variable |
| --- | --- |
| `customer_id` | `GOOGLE_WORKSPACE_CUSTOMER_ID` |

## Example

```python
from posture import CCM

ccm = CCM("google_workspace")  # credentials from GOOGLE_WORKSPACE_SERVICE_ACCOUNT_JSON_PATH, GOOGLE_WORKSPACE_ADMIN_EMAIL
df = ccm.collect("group_members")
df = ccm.collect("groups")
df = ccm.collect("org_units")
df = ccm.collect("role_assignments")
df = ccm.collect("roles")
df = ccm.collect("users")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("google_workspace")  # credentials from GOOGLE_WORKSPACE_SERVICE_ACCOUNT_JSON_PATH, GOOGLE_WORKSPACE_ADMIN_EMAIL

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [group_members](#group_members)
- [groups](#groups)
- [org_units](#org_units)
- [role_assignments](#role_assignments)
- [roles](#roles)
- [users](#users)

### group_members

| Column | Type |
| --- | --- |
| `group_id` | `str` |
| `member_id` | `str` |
| `email` | `str` |
| `role` | `str` |
| `type` | `str` |
| `status` | `str` |

### groups

| Column | Type |
| --- | --- |
| `group_id` | `str` |
| `email` | `str` |
| `name` | `str` |
| `description` | `str` |
| `admin_created` | `bool` |
| `direct_members_count` | `int` |
| `aliases` | `json` |

### org_units

| Column | Type |
| --- | --- |
| `org_unit_id` | `str` |
| `org_unit_path` | `str` |
| `name` | `str` |
| `description` | `str` |
| `parent_org_unit_id` | `str` |
| `parent_org_unit_path` | `str` |
| `block_inheritance` | `bool` |

### role_assignments

| Column | Type |
| --- | --- |
| `role_assignment_id` | `str` |
| `role_id` | `str` |
| `assigned_to` | `str` |
| `assignee_type` | `str` |
| `scope_type` | `str` |
| `org_unit_id` | `str` |

### roles

| Column | Type |
| --- | --- |
| `role_id` | `str` |
| `role_name` | `str` |
| `role_description` | `str` |
| `is_super_admin_role` | `bool` |
| `is_system_role` | `bool` |
| `role_privileges` | `json` |

### users

| Column | Type |
| --- | --- |
| `user_id` | `str` |
| `primary_email` | `str` |
| `full_name` | `str` |
| `given_name` | `str` |
| `family_name` | `str` |
| `is_admin` | `bool` |
| `is_delegated_admin` | `bool` |
| `suspended` | `bool` |
| `suspension_reason` | `str` |
| `archived` | `bool` |
| `org_unit_path` | `str` |
| `is_enforced_in_2sv` | `bool` |
| `is_enrolled_in_2sv` | `bool` |
| `last_login_time` | `datetime` |
| `creation_time` | `datetime` |
| `change_password_at_next_login` | `bool` |
| `ip_whitelisted` | `bool` |
| `agreed_to_terms` | `bool` |
| `recovery_email` | `str` |
| `recovery_phone` | `str` |
| `include_in_global_address_list` | `bool` |

