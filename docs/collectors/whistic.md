# Whistic

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `token` | `WHISTIC_TOKEN` |

## Example

```python
from posture import CCM

ccm = CCM("whistic")  # credentials from WHISTIC_TOKEN
df = ccm.collect("vendor_details")
df = ccm.collect("vendors")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("whistic")  # credentials from WHISTIC_TOKEN

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [vendor_details](#vendor_details)
- [vendors](#vendors)

### vendor_details

| Column | Type |
| --- | --- |
| `identifier` | `str` |
| `name` | `str` |
| `url` | `str` |
| `service` | `str` |
| `status` | `str` |
| `description` | `str` |
| `created_date` | `datetime` |
| `last_modified_date` | `datetime` |
| `assessment_progress` | `str` |
| `questionnaire_progress` | `str` |
| `internal_users` | `str` |
| `contract_value` | `str` |
| `billing_terms` | `str` |
| `payment_cadence` | `str` |
| `payment_method` | `str` |
| `contract_start_date` | `datetime` |
| `contract_end_date` | `datetime` |
| `billing_address_city` | `str` |
| `billing_address_state` | `str` |
| `billing_address_country` | `str` |
| `criticality` | `str` |
| `business_unit` | `str` |
| `inherent_risk` | `str` |
| `residual_risk` | `str` |
| `renewal_frequency` | `int` |
| `renewal_cadence` | `str` |
| `renewal_next_questionnaire_date` | `datetime` |
| `score` | `int` |
| `score_rating` | `str` |
| `enable_smart_search` | `bool` |
| `external_contacts` | `json` |
| `internal_contacts` | `json` |
| `internal_systems` | `json` |
| `data_types` | `json` |
| `notes` | `json` |
| `custom_attributes` | `json` |

### vendors

| Column | Type |
| --- | --- |
| `identifier` | `str` |
| `name` | `str` |
| `url` | `str` |
| `service` | `str` |
| `status` | `str` |
| `assessment_progress` | `str` |
| `questionnaire_progress` | `str` |
| `created_date` | `datetime` |
| `score` | `int` |
| `score_rating` | `str` |
| `inherent_risk` | `str` |
| `residual_risk` | `str` |
| `criticality` | `str` |

