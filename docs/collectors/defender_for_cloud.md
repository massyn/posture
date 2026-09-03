# Microsoft Defender for Cloud

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `tenant_id` | `DEFENDER_FOR_CLOUD_TENANT_ID` |
| `client_id` | `DEFENDER_FOR_CLOUD_CLIENT_ID` |
| `client_secret` | `DEFENDER_FOR_CLOUD_CLIENT_SECRET` |
| `subscription_id` | `DEFENDER_FOR_CLOUD_SUBSCRIPTION_ID` |


## Example

```python
from posture import CCM

ccm = CCM("defender_for_cloud")  # credentials from DEFENDER_FOR_CLOUD_TENANT_ID, DEFENDER_FOR_CLOUD_CLIENT_ID, DEFENDER_FOR_CLOUD_CLIENT_SECRET, DEFENDER_FOR_CLOUD_SUBSCRIPTION_ID
df = ccm.collect("alerts")
df = ccm.collect("assessments")
df = ccm.collect("regulatory_compliance_standards")
df = ccm.collect("secure_score_controls")
df = ccm.collect("secure_scores")
df = ccm.collect("sub_assessments")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("defender_for_cloud")  # credentials from DEFENDER_FOR_CLOUD_TENANT_ID, DEFENDER_FOR_CLOUD_CLIENT_ID, DEFENDER_FOR_CLOUD_CLIENT_SECRET, DEFENDER_FOR_CLOUD_SUBSCRIPTION_ID

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [alerts](#alerts)
- [assessments](#assessments)
- [regulatory_compliance_standards](#regulatory_compliance_standards)
- [secure_score_controls](#secure_score_controls)
- [secure_scores](#secure_scores)
- [sub_assessments](#sub_assessments)

### alerts

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `alert_display_name` | `str` |
| `alert_type` | `str` |
| `severity` | `str` |
| `status` | `str` |
| `intent` | `str` |
| `description` | `str` |
| `compromised_entity` | `str` |
| `vendor_name` | `str` |
| `product_name` | `str` |
| `start_time_utc` | `datetime` |
| `end_time_utc` | `datetime` |
| `time_generated_utc` | `datetime` |
| `processing_end_time_utc` | `datetime` |
| `resource_identifiers` | `json` |
| `entities` | `json` |
| `techniques` | `json` |

### assessments

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `display_name` | `str` |
| `status_code` | `str` |
| `status_cause` | `str` |
| `status_description` | `str` |
| `resource_id` | `str` |
| `resource_source` | `str` |
| `severity` | `str` |
| `assessment_type` | `str` |
| `description` | `str` |
| `remediation_description` | `str` |
| `categories` | `json` |

### regulatory_compliance_standards

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `state` | `str` |
| `passed_controls` | `int` |
| `failed_controls` | `int` |
| `skipped_controls` | `int` |
| `unsupported_controls` | `int` |

### secure_score_controls

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `display_name` | `str` |
| `healthy_resource_count` | `int` |
| `unhealthy_resource_count` | `int` |
| `not_applicable_resource_count` | `int` |
| `current_score` | `float` |
| `max_score` | `int` |
| `percentage` | `float` |
| `weight` | `int` |
| `control_type` | `str` |
| `description` | `str` |

### secure_scores

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `display_name` | `str` |
| `current_score` | `float` |
| `max_score` | `int` |
| `percentage` | `float` |
| `weight` | `int` |

### sub_assessments

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `display_name` | `str` |
| `status_code` | `str` |
| `status_severity` | `str` |
| `category` | `str` |
| `description` | `str` |
| `impact` | `str` |
| `remediation` | `str` |
| `time_generated` | `datetime` |
| `resource_id` | `str` |
| `assessed_resource_type` | `str` |
| `additional_data` | `json` |

