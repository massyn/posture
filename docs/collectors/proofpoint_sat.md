# Proofpoint Security Awareness Training

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `token` | `PROOFPOINT_SAT_TOKEN` |

### Optional

| Config key | Environment variable |
| --- | --- |
| `region` | `PROOFPOINT_SAT_REGION` |

## Example

```python
from posture import CCM

ccm = CCM("proofpoint_sat")  # credentials from PROOFPOINT_SAT_TOKEN
df = ccm.collect("cyberstrength")
df = ccm.collect("phishalarm")
df = ccm.collect("phishing")
df = ccm.collect("training")
df = ccm.collect("users")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("proofpoint_sat")  # credentials from PROOFPOINT_SAT_TOKEN

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [cyberstrength](#cyberstrength)
- [phishalarm](#phishalarm)
- [phishing](#phishing)
- [training](#training)
- [users](#users)

### cyberstrength

| Column | Type |
| --- | --- |
| `id` | `str` |
| `user_first_name` | `str` |
| `user_last_name` | `str` |
| `user_email_address` | `str` |
| `user_active` | `bool` |
| `user_deleted_date` | `datetime` |
| `sso_id` | `str` |
| `user_tags` | `json` |
| `assignment_name` | `str` |
| `assignment_status` | `str` |
| `assignment_start_date` | `datetime` |
| `assignment_due_date` | `datetime` |
| `assignment_deleted_date` | `datetime` |
| `assignment_average_score` | `float` |
| `assessment_name` | `str` |
| `assessment_status` | `str` |
| `assessment_type` | `str` |
| `user_assignment_status` | `str` |
| `user_removed_from_assignment` | `bool` |
| `user_correct_on_assignment` | `int` |
| `user_answered_on_assignment` | `int` |
| `user_score_on_assignment` | `float` |
| `company_average_score` | `float` |
| `category` | `str` |
| `category_benchmark_all` | `float` |
| `category_benchmark_industry` | `float` |
| `questions_in_category` | `int` |
| `is_ae_enabled` | `bool` |
| `attempt_date` | `datetime` |
| `seconds_in_attempt` | `int` |
| `question_id` | `str` |
| `question_type` | `str` |
| `question_text` | `str` |
| `question_date` | `datetime` |
| `question_latency` | `int` |
| `custom_question` | `bool` |
| `selected_answer` | `str` |
| `correct` | `bool` |

### phishalarm

| Column | Type |
| --- | --- |
| `id` | `str` |
| `user_first_name` | `str` |
| `user_last_name` | `str` |
| `user_email_address` | `str` |
| `user_active` | `bool` |
| `user_deleted_date` | `datetime` |
| `sso_id` | `str` |
| `user_tags` | `json` |
| `campaign_name` | `str` |
| `action` | `str` |
| `email_type` | `str` |
| `received_date` | `datetime` |
| `reported_date` | `datetime` |
| `elapsed_hours` | `float` |
| `os` | `str` |
| `email_client_version` | `str` |
| `assessment_soft_deleted_date` | `datetime` |

### phishing

| Column | Type |
| --- | --- |
| `id` | `str` |
| `user_first_name` | `str` |
| `user_last_name` | `str` |
| `user_email_address` | `str` |
| `user_active` | `bool` |
| `user_deleted_date` | `datetime` |
| `sso_id` | `str` |
| `user_tags` | `json` |
| `sent_timestamp` | `datetime` |
| `event_timestamp` | `datetime` |
| `event_type` | `str` |
| `campaign_name` | `str` |
| `campaign_type` | `str` |
| `campaign_status` | `str` |
| `campaign_start_date` | `datetime` |
| `campaign_end_date` | `datetime` |
| `auto_enrollment` | `bool` |
| `template_name` | `str` |
| `template_subject` | `str` |
| `assessment_archived` | `bool` |

### training

| Column | Type |
| --- | --- |
| `id` | `str` |
| `user_first_name` | `str` |
| `user_last_name` | `str` |
| `user_email_address` | `str` |
| `user_active` | `bool` |
| `user_deleted_date` | `datetime` |
| `sso_id` | `str` |
| `user_tags` | `json` |
| `user_assignment_status` | `str` |
| `assignment_name` | `str` |
| `assignment_start_date` | `datetime` |
| `assignment_due_date` | `datetime` |
| `assignment_deleted_date` | `datetime` |
| `assignment_status` | `str` |
| `assignment_method` | `str` |
| `assignment_deleted` | `bool` |
| `duration` | `str` |
| `auto_enroll` | `bool` |
| `module_name_admin` | `str` |
| `module_name_user` | `str` |
| `module_type` | `str` |
| `module_attempt_date` | `datetime` |
| `module_last_action` | `str` |
| `seconds_in_module_attempt` | `int` |
| `module_attempt_end_status` | `str` |
| `module_attempt_status` | `str` |
| `module_attempt_score` | `float` |
| `module_attempt_score_correct` | `int` |
| `module_attempt_score_answered` | `int` |
| `user_removed_from_assignment` | `bool` |
| `freeplay` | `bool` |
| `force_completed_date` | `datetime` |

### users

| Column | Type |
| --- | --- |
| `id` | `str` |
| `user_first_name` | `str` |
| `user_last_name` | `str` |
| `user_email_address` | `str` |
| `user_active` | `bool` |
| `user_deleted_date` | `datetime` |
| `sso_id` | `str` |
| `user_tags` | `json` |
| `locale` | `str` |
| `timezone` | `str` |
| `data_last_updated` | `datetime` |

