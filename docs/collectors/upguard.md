# UpGuard

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `api_key` | `UPGUARD_API_KEY` |

## Example

```python
from posture import CCM

ccm = CCM("upguard")  # credentials from UPGUARD_API_KEY
df = ccm.collect("breached_identities")
df = ccm.collect("domains")
df = ccm.collect("organisation")
df = ccm.collect("questionnaire_risks")
df = ccm.collect("vendor_risks")
df = ccm.collect("vendors")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("upguard")  # credentials from UPGUARD_API_KEY

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [breached_identities](#breached_identities)
- [domains](#domains)
- [organisation](#organisation)
- [questionnaire_risks](#questionnaire_risks)
- [vendor_risks](#vendor_risks)
- [vendors](#vendors)

### breached_identities

| Column | Type |
| --- | --- |
| `breached_identity_id` | `str` |
| `identity_name` | `str` |
| `domain` | `str` |
| `last_breach_date` | `datetime` |
| `num_breaches` | `int` |
| `vip` | `bool` |
| `ignored` | `bool` |
| `severity` | `str` |

### domains

| Column | Type |
| --- | --- |
| `domain_hostname` | `str` |
| `active` | `bool` |
| `primary_domain` | `bool` |

### organisation

| Column | Type |
| --- | --- |
| `organisation_id` | `str` |
| `organisation_name` | `str` |
| `primary_hostname` | `str` |
| `automated_score` | `int` |
| `website_security_score` | `int` |
| `email_security_score` | `int` |
| `network_security_score` | `int` |
| `ip_domain_reputation_score` | `int` |
| `operational_risk_score` | `int` |
| `attack_surface_score` | `int` |
| `vulnerability_management_score` | `int` |
| `encryption_score` | `int` |
| `dns_score` | `int` |
| `data_leakage_score` | `int` |
| `brand_reputation_score` | `int` |

### questionnaire_risks

| Column | Type |
| --- | --- |
| `risk_id` | `str` |
| `vendor_id` | `int` |
| `questionnaire_id` | `int` |
| `risk_name` | `str` |
| `risk_category` | `str` |
| `risk_severity` | `str` |
| `risk_text` | `str` |
| `risk_explanation` | `str` |
| `risk_why` | `str` |
| `in_remediation` | `bool` |
| `is_shared_questionnaire` | `bool` |
| `created_at` | `datetime` |
| `controls` | `json` |
| `risk_waivers` | `json` |

### vendor_risks

| Column | Type |
| --- | --- |
| `risk_id` | `str` |
| `finding` | `str` |
| `risk_description` | `str` |
| `severity` | `str` |
| `category` | `str` |
| `first_detected` | `datetime` |
| `requested_primary_hostname` | `str` |

### vendors

| Column | Type |
| --- | --- |
| `vendor_id` | `str` |
| `vendor_name` | `str` |
| `primary_hostname` | `str` |
| `score` | `int` |
| `overall_score` | `int` |
| `automated_score` | `int` |
| `website_security_score` | `int` |
| `email_security_score` | `int` |
| `network_security_score` | `int` |
| `ip_domain_reputation_score` | `int` |
| `operational_risk_score` | `int` |
| `attack_surface_score` | `int` |
| `vulnerability_management_score` | `int` |
| `encryption_score` | `int` |
| `dns_score` | `int` |
| `data_leakage_score` | `int` |
| `brand_reputation_score` | `int` |
| `tier` | `str` |
| `monitored` | `bool` |
| `assessment_status` | `str` |
| `last_assessed` | `datetime` |

