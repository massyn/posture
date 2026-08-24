# SonarCloud

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `token` | `SONARCLOUD_TOKEN` |
| `organization` | `SONARCLOUD_ORGANIZATION` |


## Example

```python
from posture import CCM

ccm = CCM("sonarcloud")  # credentials from SONARCLOUD_TOKEN, SONARCLOUD_ORGANIZATION
df = ccm.collect("hotspots")
df = ccm.collect("issues")
df = ccm.collect("measures")
df = ccm.collect("organizations")
df = ccm.collect("projects")
df = ccm.collect("quality_gate_status")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("sonarcloud")  # credentials from SONARCLOUD_TOKEN, SONARCLOUD_ORGANIZATION

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [hotspots](#hotspots)
- [issues](#issues)
- [measures](#measures)
- [organizations](#organizations)
- [projects](#projects)
- [quality_gate_status](#quality_gate_status)

### hotspots

| Column | Type |
| --- | --- |
| `project_key` | `str` |
| `key` | `str` |
| `component` | `str` |
| `project` | `str` |
| `security_category` | `str` |
| `vulnerability_probability` | `str` |
| `status` | `str` |
| `resolution` | `str` |
| `line` | `int` |
| `message` | `str` |
| `author` | `str` |
| `creation_date` | `datetime` |
| `update_date` | `datetime` |

### issues

| Column | Type |
| --- | --- |
| `key` | `str` |
| `rule` | `str` |
| `severity` | `str` |
| `component` | `str` |
| `project` | `str` |
| `line` | `int` |
| `status` | `str` |
| `resolution` | `str` |
| `type` | `str` |
| `message` | `str` |
| `effort` | `str` |
| `tags` | `json` |
| `author` | `str` |
| `creation_date` | `datetime` |
| `update_date` | `datetime` |

### measures

| Column | Type |
| --- | --- |
| `project_key` | `str` |
| `metric` | `str` |
| `value` | `str` |
| `best_value` | `bool` |

### organizations

| Column | Type |
| --- | --- |
| `key` | `str` |
| `name` | `str` |
| `description` | `str` |
| `url` | `str` |
| `avatar` | `str` |
| `subscription` | `str` |

### projects

| Column | Type |
| --- | --- |
| `key` | `str` |
| `name` | `str` |
| `qualifier` | `str` |
| `visibility` | `str` |
| `last_analysis_date` | `datetime` |

### quality_gate_status

| Column | Type |
| --- | --- |
| `project_key` | `str` |
| `status` | `str` |
| `conditions` | `json` |
| `period` | `json` |

