# SecurityScorecard

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `token` | `SECURITYSCORECARD_TOKEN` |


## Example

```python
from posture import CCM

ccm = CCM("securityscorecard")  # credentials from SECURITYSCORECARD_TOKEN
df = ccm.collect("company_factors")
df = ccm.collect("portfolio_companies")
df = ccm.collect("portfolios")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("securityscorecard")  # credentials from SECURITYSCORECARD_TOKEN

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [company_factors](#company_factors)
- [portfolio_companies](#portfolio_companies)
- [portfolios](#portfolios)

### company_factors

| Column | Type |
| --- | --- |
| `domain` | `str` |
| `name` | `str` |
| `score` | `int` |
| `grade` | `str` |
| `issue_summary` | `json` |

### portfolio_companies

| Column | Type |
| --- | --- |
| `portfolio_id` | `str` |
| `domain` | `str` |
| `name` | `str` |
| `score` | `int` |
| `grade` | `str` |
| `grade_url` | `str` |
| `industry` | `str` |
| `size` | `str` |
| `last30day_score_change` | `int` |
| `total_issue_count` | `int` |
| `created_at` | `datetime` |

### portfolios

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `description` | `str` |
| `privacy` | `str` |
| `created_by` | `str` |

