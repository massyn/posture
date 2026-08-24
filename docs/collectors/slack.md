# Slack

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `token` | `SLACK_TOKEN` |


## Example

```python
from posture import CCM

ccm = CCM("slack")  # credentials from SLACK_TOKEN
df = ccm.collect("apps")
df = ccm.collect("channel_members")
df = ccm.collect("channels")
df = ccm.collect("user_groups")
df = ccm.collect("users")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("slack")  # credentials from SLACK_TOKEN

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [apps](#apps)
- [channel_members](#channel_members)
- [channels](#channels)
- [user_groups](#user_groups)
- [users](#users)

### apps

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `description` | `str` |
| `is_app_directory_approved` | `bool` |
| `is_internal` | `bool` |
| `developer_type` | `str` |
| `socket_mode_enabled` | `bool` |
| `scopes` | `json` |
| `date_updated` | `datetime` |
| `last_resolved_by_actor_id` | `str` |
| `last_resolved_by_actor_type` | `str` |

### channel_members

| Column | Type |
| --- | --- |
| `channel_id` | `str` |
| `user_id` | `str` |

### channels

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `purpose` | `str` |
| `member_count` | `int` |
| `created` | `datetime` |
| `creator_id` | `str` |
| `is_private` | `bool` |
| `is_archived` | `bool` |
| `is_general` | `bool` |
| `last_activity_ts` | `int` |
| `is_ext_shared` | `bool` |
| `is_global_shared` | `bool` |
| `is_org_shared` | `bool` |
| `is_org_default` | `bool` |
| `is_org_mandatory` | `bool` |
| `is_frozen` | `bool` |
| `is_pending_ext_shared` | `bool` |
| `connected_team_ids` | `json` |

### user_groups

| Column | Type |
| --- | --- |
| `id` | `str` |
| `team_id` | `str` |
| `name` | `str` |
| `description` | `str` |
| `handle` | `str` |
| `is_external` | `bool` |
| `date_create` | `datetime` |
| `date_update` | `datetime` |
| `date_delete` | `int` |
| `auto_type` | `str` |
| `created_by` | `str` |
| `updated_by` | `str` |
| `deleted_by` | `str` |
| `user_count` | `int` |

### users

| Column | Type |
| --- | --- |
| `id` | `str` |
| `email` | `str` |
| `username` | `str` |
| `full_name` | `str` |
| `is_admin` | `bool` |
| `is_owner` | `bool` |
| `is_primary_owner` | `bool` |
| `is_restricted` | `bool` |
| `is_ultra_restricted` | `bool` |
| `is_bot` | `bool` |
| `is_active` | `bool` |
| `has_2fa` | `bool` |
| `has_sso` | `bool` |
| `date_created` | `datetime` |
| `deactivated_ts` | `int` |
| `expiration_ts` | `int` |
| `workspaces` | `json` |

