# Miro

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `access_token` | `MIRO_ACCESS_TOKEN` |

### Optional

| Config key | Environment variable |
| --- | --- |
| `base_url` | `MIRO_BASE_URL` |

## Example

```python
from posture import CCM

ccm = CCM("miro")  # credentials from MIRO_ACCESS_TOKEN
df = ccm.collect("audit_logs")
df = ccm.collect("board_classifications")
df = ccm.collect("board_members")
df = ccm.collect("boards")
df = ccm.collect("org_members")
df = ccm.collect("team_members")
df = ccm.collect("teams")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("miro")  # credentials from MIRO_ACCESS_TOKEN

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [audit_logs](#audit_logs)
- [board_classifications](#board_classifications)
- [board_members](#board_members)
- [boards](#boards)
- [org_members](#org_members)
- [team_members](#team_members)
- [teams](#teams)

### audit_logs

| Column | Type |
| --- | --- |
| `id` | `str` |
| `event` | `str` |
| `category` | `str` |
| `created_at` | `datetime` |
| `created_by_id` | `str` |
| `created_by_name` | `str` |
| `created_by_email` | `str` |
| `object_id` | `str` |
| `object_name` | `str` |
| `context_ip` | `str` |
| `context_team_id` | `str` |
| `context_organization_id` | `str` |
| `details` | `json` |

### board_classifications

| Column | Type |
| --- | --- |
| `board_id` | `str` |
| `board_name` | `str` |
| `label_id` | `str` |
| `label_name` | `str` |
| `color` | `str` |
| `description` | `str` |
| `sharing_recommendation` | `str` |
| `guideline_url` | `str` |

### board_members

| Column | Type |
| --- | --- |
| `board_id` | `str` |
| `board_name` | `str` |
| `id` | `str` |
| `name` | `str` |
| `role` | `str` |

### boards

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `description` | `str` |
| `team_id` | `str` |
| `team_name` | `str` |
| `project_id` | `str` |
| `view_link` | `str` |
| `owner_id` | `str` |
| `owner_name` | `str` |
| `created_at` | `datetime` |
| `created_by_id` | `str` |
| `created_by_name` | `str` |
| `modified_at` | `datetime` |
| `modified_by_id` | `str` |
| `last_opened_at` | `datetime` |
| `sharing_access` | `str` |
| `sharing_organization_access` | `str` |
| `sharing_team_access` | `str` |
| `sharing_invite_access` | `str` |
| `sharing_password_required` | `bool` |
| `perm_collaboration_tools_start_access` | `str` |
| `perm_copy_access` | `str` |
| `perm_sharing_access` | `str` |

### org_members

| Column | Type |
| --- | --- |
| `id` | `str` |
| `email` | `str` |
| `active` | `bool` |
| `license` | `str` |
| `role` | `str` |
| `last_activity_at` | `datetime` |
| `license_assigned_at` | `datetime` |
| `admin_roles` | `json` |

### team_members

| Column | Type |
| --- | --- |
| `team_id` | `str` |
| `id` | `str` |
| `role` | `str` |
| `created_at` | `datetime` |
| `created_by` | `str` |
| `modified_at` | `datetime` |
| `modified_by` | `str` |

### teams

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |

