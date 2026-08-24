# Microsoft Teams

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `tenant_id` | `TEAMS_TENANT_ID` |
| `client_id` | `TEAMS_CLIENT_ID` |
| `client_secret` | `TEAMS_CLIENT_SECRET` |


## Example

```python
from posture import CCM

ccm = CCM("teams")  # credentials from TEAMS_TENANT_ID, TEAMS_CLIENT_ID, TEAMS_CLIENT_SECRET
df = ccm.collect("channels")
df = ccm.collect("installed_apps")
df = ccm.collect("team_members")
df = ccm.collect("team_settings")
df = ccm.collect("teams")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("teams")  # credentials from TEAMS_TENANT_ID, TEAMS_CLIENT_ID, TEAMS_CLIENT_SECRET

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [channels](#channels)
- [installed_apps](#installed_apps)
- [team_members](#team_members)
- [team_settings](#team_settings)
- [teams](#teams)

### channels

| Column | Type |
| --- | --- |
| `team_id` | `str` |
| `channel_id` | `str` |
| `display_name` | `str` |
| `description` | `str` |
| `membership_type` | `str` |
| `is_archived` | `bool` |
| `created_date_time` | `datetime` |
| `web_url` | `str` |

### installed_apps

| Column | Type |
| --- | --- |
| `team_id` | `str` |
| `installation_id` | `str` |
| `teams_app_id` | `str` |
| `azure_ad_app_id` | `str` |
| `display_name` | `str` |
| `version` | `str` |
| `publishing_state` | `str` |

### team_members

| Column | Type |
| --- | --- |
| `team_id` | `str` |
| `membership_id` | `str` |
| `roles` | `json` |
| `display_name` | `str` |
| `user_id` | `str` |
| `email` | `str` |

### team_settings

| Column | Type |
| --- | --- |
| `team_id` | `str` |
| `is_archived` | `bool` |
| `member_allow_create_update_channels` | `bool` |
| `member_allow_delete_channels` | `bool` |
| `member_allow_add_remove_apps` | `bool` |
| `member_allow_create_update_remove_tabs` | `bool` |
| `member_allow_create_update_remove_connectors` | `bool` |
| `guest_allow_create_update_channels` | `bool` |
| `guest_allow_delete_channels` | `bool` |
| `messaging_allow_user_edit_messages` | `bool` |
| `messaging_allow_user_delete_messages` | `bool` |
| `messaging_allow_owner_delete_messages` | `bool` |
| `messaging_allow_team_mentions` | `bool` |
| `messaging_allow_channel_mentions` | `bool` |
| `discovery_show_in_search` | `bool` |
| `owners_count` | `int` |
| `members_count` | `int` |
| `guests_count` | `int` |

### teams

| Column | Type |
| --- | --- |
| `team_id` | `str` |
| `display_name` | `str` |
| `description` | `str` |
| `mail_nickname` | `str` |
| `visibility` | `str` |
| `mail_enabled` | `bool` |
| `created_date_time` | `datetime` |

