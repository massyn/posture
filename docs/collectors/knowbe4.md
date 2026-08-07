# KnowBe4

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `token` | `KNOWBE4_TOKEN` |

## Example

```python
from posture import CCM

ccm = CCM("knowbe4")  # credentials from KNOWBE4_TOKEN
df = ccm.collect("pst_recipients")
df = ccm.collect("psts")
df = ccm.collect("training_enrollments")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("knowbe4")  # credentials from KNOWBE4_TOKEN

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [pst_recipients](#pst_recipients)
- [psts](#psts)
- [training_enrollments](#training_enrollments)

### pst_recipients

| Column | Type |
| --- | --- |
| `pst_id` | `int` |
| `recipient_id` | `int` |
| `user_id` | `int` |
| `user_first_name` | `str` |
| `user_last_name` | `str` |
| `user_email` | `str` |
| `template_name` | `str` |
| `scheduled_at` | `datetime` |
| `delivered_at` | `datetime` |
| `opened_at` | `datetime` |
| `clicked_at` | `datetime` |
| `replied_at` | `datetime` |
| `attachment_opened_at` | `datetime` |
| `macro_enabled_at` | `datetime` |
| `data_entered_at` | `datetime` |
| `qr_code_scanned_at` | `datetime` |
| `reported_at` | `datetime` |
| `bounced_at` | `datetime` |
| `ip` | `str` |
| `ip_location` | `str` |
| `browser` | `str` |
| `browser_version` | `str` |
| `os` | `str` |

### psts

| Column | Type |
| --- | --- |
| `pst_id` | `int` |
| `campaign_id` | `int` |
| `name` | `str` |
| `status` | `str` |
| `groups` | `json` |
| `phish_prone_percentage` | `float` |
| `started_at` | `datetime` |
| `duration` | `int` |
| `categories` | `json` |
| `template_id` | `int` |
| `landing_page_id` | `int` |
| `scheduled_count` | `int` |
| `delivered_count` | `int` |
| `opened_count` | `int` |
| `clicked_count` | `int` |
| `replied_count` | `int` |
| `attachment_open_count` | `int` |
| `macro_enabled_count` | `int` |
| `data_entered_count` | `int` |
| `qr_code_scanned_count` | `int` |
| `reported_count` | `int` |
| `bounced_count` | `int` |

### training_enrollments

| Column | Type |
| --- | --- |
| `enrollment_id` | `int` |
| `user_id` | `int` |
| `user_email` | `str` |
| `user_first_name` | `str` |
| `user_last_name` | `str` |
| `content_type` | `str` |
| `module_name` | `str` |
| `campaign_name` | `str` |
| `enrollment_date` | `datetime` |
| `start_date` | `datetime` |
| `completion_date` | `datetime` |
| `status` | `str` |
| `time_spent` | `int` |

