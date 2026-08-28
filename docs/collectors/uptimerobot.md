# UptimeRobot

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `token` | `UPTIME_ROBOT_TOKEN` |


## Example

```python
from posture import CCM

ccm = CCM("uptimerobot")  # credentials from UPTIME_ROBOT_TOKEN
df = ccm.collect("account")
df = ccm.collect("alert_contacts")
df = ccm.collect("monitor_logs")
df = ccm.collect("monitor_response_times")
df = ccm.collect("monitors")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("uptimerobot")  # credentials from UPTIME_ROBOT_TOKEN

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [account](#account)
- [alert_contacts](#alert_contacts)
- [monitor_logs](#monitor_logs)
- [monitor_response_times](#monitor_response_times)
- [monitors](#monitors)

### account

| Column | Type |
| --- | --- |
| `email` | `str` |
| `user_id` | `str` |
| `firstname` | `str` |
| `sms_credits` | `int` |
| `payment_period` | `str` |
| `subscription_expiry_date` | `datetime` |
| `monitor_limit` | `int` |
| `monitor_interval` | `int` |
| `up_monitors` | `int` |
| `down_monitors` | `int` |
| `paused_monitors` | `int` |
| `total_monitors_count` | `int` |
| `active_subscription` | `str` |
| `registered_at` | `datetime` |

### alert_contacts

| Column | Type |
| --- | --- |
| `id` | `str` |
| `friendly_name` | `str` |
| `type` | `int` |
| `status` | `int` |
| `value` | `str` |

### monitor_logs

| Column | Type |
| --- | --- |
| `monitor_id` | `str` |
| `monitor_friendly_name` | `str` |
| `type` | `int` |
| `datetime` | `datetime` |
| `duration` | `int` |
| `reason_code` | `str` |
| `reason_detail` | `str` |

### monitor_response_times

| Column | Type |
| --- | --- |
| `monitor_id` | `str` |
| `monitor_friendly_name` | `str` |
| `datetime` | `datetime` |
| `response_time_ms` | `int` |

### monitors

| Column | Type |
| --- | --- |
| `id` | `str` |
| `friendly_name` | `str` |
| `url` | `str` |
| `type` | `int` |
| `sub_type` | `str` |
| `keyword_type` | `int` |
| `keyword_value` | `str` |
| `port` | `str` |
| `interval` | `int` |
| `timeout` | `int` |
| `status` | `int` |
| `create_datetime` | `datetime` |
| `average_response_time` | `float` |
| `all_time_uptime_ratio` | `float` |
| `uptime_ratio_1d` | `float` |
| `uptime_ratio_7d` | `float` |
| `uptime_ratio_30d` | `float` |
| `uptime_ratio_90d` | `float` |
| `down_duration_1d` | `int` |
| `down_duration_7d` | `int` |
| `down_duration_30d` | `int` |
| `down_duration_90d` | `int` |

