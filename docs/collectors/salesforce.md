# Salesforce

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `username` | `SALESFORCE_USERNAME` |
| `password` | `SALESFORCE_PASSWORD` |
| `token` | `SALESFORCE_TOKEN` |

## Example

```python
from posture import CCM

ccm = CCM("salesforce")  # credentials from SALESFORCE_USERNAME, SALESFORCE_PASSWORD, SALESFORCE_TOKEN
df = ccm.collect("domain__c")
df = ccm.collect("fixed_asset__c")
df = ccm.collect("krow__location__c")
df = ccm.collect("krow__project_resources__c")
df = ccm.collect("krow__team__c")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("salesforce")  # credentials from SALESFORCE_USERNAME, SALESFORCE_PASSWORD, SALESFORCE_TOKEN

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [domain__c](#domain__c)
- [fixed_asset__c](#fixed_asset__c)
- [krow__location__c](#krow__location__c)
- [krow__project_resources__c](#krow__project_resources__c)
- [krow__team__c](#krow__team__c)

### domain__c

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `active__c` | `bool` |

### fixed_asset__c

| Column | Type |
| --- | --- |
| `id` | `str` |
| `project_resource__c` | `str` |
| `possession__c` | `str` |
| `status__c` | `str` |
| `type__c` | `str` |
| `serial_number__c` | `str` |
| `model__c` | `str` |
| `active__c` | `bool` |

### krow__location__c

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |

### krow__project_resources__c

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `user_email__c` | `str` |
| `employment_end_date__c` | `datetime` |
| `legal_name__c` | `str` |
| `domain__c` | `str` |
| `employment_start_date__c` | `datetime` |
| `krow__team__c` | `str` |
| `krow__active__c` | `bool` |
| `krow__location__c` | `str` |

### krow__team__c

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `active__c` | `bool` |

