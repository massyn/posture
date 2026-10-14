# HCL BigFix

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `endpoint` | `BIGFIX_ENDPOINT` |
| `username` | `BIGFIX_USERNAME` |
| `password` | `BIGFIX_PASSWORD` |

### Optional

| Config key | Environment variable |
| --- | --- |
| `ca_bundle` | `BIGFIX_CA_BUNDLE` |
| `insecure` | `BIGFIX_INSECURE` |

## Example

```python
from posture import CCM

ccm = CCM("bigfix")  # credentials from BIGFIX_ENDPOINT, BIGFIX_USERNAME, BIGFIX_PASSWORD
df = ccm.collect("computers")
df = ccm.collect("fixlet_results")
df = ccm.collect("fixlets")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("bigfix")  # credentials from BIGFIX_ENDPOINT, BIGFIX_USERNAME, BIGFIX_PASSWORD

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [computers](#computers)
- [fixlet_results](#fixlet_results)
- [fixlets](#fixlets)

### computers

| Column | Type |
| --- | --- |
| `id` | `int` |
| `name` | `str` |
| `operating_system` | `str` |
| `cpu` | `str` |
| `computer_type` | `str` |
| `agent_type` | `str` |
| `agent_version` | `str` |
| `ip_addresses` | `str` |
| `user_names` | `str` |
| `relay_server` | `str` |
| `locked` | `bool` |
| `last_report_time` | `datetime` |

### fixlet_results

| Column | Type |
| --- | --- |
| `computer_id` | `int` |
| `computer_name` | `str` |
| `fixlet_id` | `int` |
| `fixlet_site_name` | `str` |
| `fixlet_name` | `str` |
| `source_severity` | `str` |
| `first_became_relevant` | `datetime` |
| `last_became_relevant` | `datetime` |

### fixlets

| Column | Type |
| --- | --- |
| `id` | `int` |
| `site_name` | `str` |
| `name` | `str` |
| `category` | `str` |
| `source` | `str` |
| `source_id` | `str` |
| `source_severity` | `str` |
| `source_release_date` | `datetime` |
| `cve_ids` | `str` |
| `applicable_computer_count` | `int` |

