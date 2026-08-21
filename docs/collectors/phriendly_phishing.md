# PhriendlyPhishing

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `client_id` | `PHRIENDLY_PHISHING_CLIENT_ID` |
| `client_secret` | `PHRIENDLY_PHISHING_CLIENT_SECRET` |


## Example

```python
from posture import CCM

ccm = CCM("phriendly_phishing")  # credentials from PHRIENDLY_PHISHING_CLIENT_ID, PHRIENDLY_PHISHING_CLIENT_SECRET
df = ccm.collect("clicks")
df = ccm.collect("trainings")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("phriendly_phishing")  # credentials from PHRIENDLY_PHISHING_CLIENT_ID, PHRIENDLY_PHISHING_CLIENT_SECRET

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [clicks](#clicks)
- [trainings](#trainings)

### clicks

| Column | Type |
| --- | --- |
| `id` | `str` |
| `user_id` | `str` |
| `email` | `str` |
| `first_name` | `str` |
| `last_name` | `str` |
| `group_name` | `str` |
| `campaign_name` | `str` |
| `template_name` | `str` |
| `sent_date` | `datetime` |
| `clicked_date` | `datetime` |
| `reported_date` | `datetime` |
| `ip_address` | `str` |
| `browser` | `str` |
| `operating_system` | `str` |

### trainings

| Column | Type |
| --- | --- |
| `id` | `str` |
| `user_id` | `str` |
| `email` | `str` |
| `first_name` | `str` |
| `last_name` | `str` |
| `group_name` | `str` |
| `training_name` | `str` |
| `status` | `str` |
| `assigned_date` | `datetime` |
| `started_date` | `datetime` |
| `completed_date` | `datetime` |
| `score` | `float` |

