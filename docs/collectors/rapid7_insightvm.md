# Rapid7 InsightVM

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `api_key` | `RAPID7_INSIGHTVM_API_KEY` |

### Optional

| Config key | Environment variable |
| --- | --- |
| `region` | `RAPID7_INSIGHTVM_REGION` |
| `endpoint` | `RAPID7_INSIGHTVM_ENDPOINT` |

## Example

```python
from posture import CCM

ccm = CCM("rapid7_insightvm")  # credentials from RAPID7_INSIGHTVM_API_KEY
df = ccm.collect("assets")
df = ccm.collect("vulnerabilities")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("rapid7_insightvm")  # credentials from RAPID7_INSIGHTVM_API_KEY

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [assets](#assets)
- [vulnerabilities](#vulnerabilities)

### assets

| Column | Type |
| --- | --- |
| `id` | `str` |
| `ip` | `str` |
| `mac` | `str` |
| `host_name` | `str` |
| `os_name` | `str` |
| `os_version` | `str` |
| `os_type` | `str` |
| `os_vendor` | `str` |
| `assessed_for_vulnerabilities` | `bool` |
| `assessed_for_policies` | `bool` |
| `risk_score` | `float` |
| `critical_vulnerabilities` | `int` |
| `severe_vulnerabilities` | `int` |
| `moderate_vulnerabilities` | `int` |
| `total_vulnerabilities` | `int` |
| `exploits` | `int` |
| `malware_kits` | `int` |
| `last_assessed_for_vulnerabilities` | `datetime` |
| `tags` | `json` |
| `addresses` | `json` |
| `host_names` | `json` |

### vulnerabilities

| Column | Type |
| --- | --- |
| `id` | `str` |
| `title` | `str` |
| `description` | `str` |
| `severity` | `str` |
| `severity_score` | `int` |
| `risk_score` | `float` |
| `cvss_v2_score` | `float` |
| `cvss_v2_vector` | `str` |
| `cvss_v3_score` | `float` |
| `cvss_v3_vector` | `str` |
| `denial_of_service` | `bool` |
| `exploits` | `int` |
| `malware_kits` | `int` |
| `published` | `datetime` |
| `added` | `datetime` |
| `modified` | `datetime` |
| `categories` | `json` |
| `cves` | `json` |
| `references` | `json` |

