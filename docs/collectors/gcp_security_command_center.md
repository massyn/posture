# GCP Security Command Center

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `service_account_json_path` | `GCP_SCC_SERVICE_ACCOUNT_JSON_PATH` |
| `organization_id` | `GCP_SCC_ORGANIZATION_ID` |


## Example

```python
from posture import CCM

ccm = CCM("gcp_security_command_center")  # credentials from GCP_SCC_SERVICE_ACCOUNT_JSON_PATH, GCP_SCC_ORGANIZATION_ID
df = ccm.collect("assets")
df = ccm.collect("findings")
df = ccm.collect("sources")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("gcp_security_command_center")  # credentials from GCP_SCC_SERVICE_ACCOUNT_JSON_PATH, GCP_SCC_ORGANIZATION_ID

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [assets](#assets)
- [findings](#findings)
- [sources](#sources)

### assets

| Column | Type |
| --- | --- |
| `name` | `str` |
| `resource_name` | `str` |
| `resource_type` | `str` |
| `resource_project` | `str` |
| `resource_display_name` | `str` |
| `resource_owners` | `json` |
| `create_time` | `datetime` |
| `update_time` | `datetime` |
| `resource_properties` | `json` |
| `iam_policy` | `str` |

### findings

| Column | Type |
| --- | --- |
| `name` | `str` |
| `canonical_name` | `str` |
| `parent` | `str` |
| `category` | `str` |
| `state` | `str` |
| `severity` | `str` |
| `finding_class` | `str` |
| `mute` | `str` |
| `description` | `str` |
| `resource_name` | `str` |
| `external_uri` | `str` |
| `cve_id` | `str` |
| `cvss_base_score` | `float` |
| `event_time` | `datetime` |
| `create_time` | `datetime` |
| `source_properties` | `json` |
| `resource_display_name` | `str` |
| `resource_type` | `str` |
| `resource_project_display_name` | `str` |
| `resource_parent_display_name` | `str` |

### sources

| Column | Type |
| --- | --- |
| `name` | `str` |
| `canonical_name` | `str` |
| `display_name` | `str` |
| `description` | `str` |

