# OWASP Dependency-Track

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `api_key` | `DEPENDENCY_TRACK_API_KEY` |
| `endpoint` | `DEPENDENCY_TRACK_ENDPOINT` |


## Example

```python
from posture import CCM

ccm = CCM("dependency_track")  # credentials from DEPENDENCY_TRACK_API_KEY, DEPENDENCY_TRACK_ENDPOINT
df = ccm.collect("project_components")
df = ccm.collect("project_findings")
df = ccm.collect("projects")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("dependency_track")  # credentials from DEPENDENCY_TRACK_API_KEY, DEPENDENCY_TRACK_ENDPOINT

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [project_components](#project_components)
- [project_findings](#project_findings)
- [projects](#projects)

### project_components

| Column | Type |
| --- | --- |
| `project_uuid` | `str` |
| `component_uuid` | `str` |
| `name` | `str` |
| `version` | `str` |
| `group` | `str` |
| `purl` | `str` |
| `cpe` | `str` |
| `classifier` | `str` |
| `scope` | `str` |
| `is_internal` | `bool` |
| `publisher` | `str` |
| `license` | `str` |
| `license_expression` | `str` |
| `resolved_license_id` | `str` |
| `md5` | `str` |
| `sha1` | `str` |
| `sha256` | `str` |
| `latest_version` | `str` |
| `last_inherited_risk_score` | `float` |

### project_findings

| Column | Type |
| --- | --- |
| `project_uuid` | `str` |
| `component_uuid` | `str` |
| `component_name` | `str` |
| `component_version` | `str` |
| `component_group` | `str` |
| `component_purl` | `str` |
| `vulnerability_uuid` | `str` |
| `vuln_id` | `str` |
| `vulnerability_source` | `str` |
| `title` | `str` |
| `severity` | `str` |
| `cvss_v2_base_score` | `float` |
| `cvss_v3_base_score` | `float` |
| `epss_score` | `float` |
| `epss_percentile` | `float` |
| `cwes` | `json` |
| `aliases` | `json` |
| `published` | `datetime` |
| `analysis_state` | `str` |
| `is_suppressed` | `bool` |
| `analyzer_identity` | `str` |
| `attributed_on` | `datetime` |
| `reference_url` | `str` |
| `matrix` | `str` |

### projects

| Column | Type |
| --- | --- |
| `project_uuid` | `str` |
| `name` | `str` |
| `version` | `str` |
| `group` | `str` |
| `description` | `str` |
| `classifier` | `str` |
| `purl` | `str` |
| `cpe` | `str` |
| `active` | `bool` |
| `inactive_since` | `datetime` |
| `is_latest` | `bool` |
| `parent_uuid` | `str` |
| `tags` | `json` |
| `last_bom_import` | `datetime` |
| `last_bom_import_format` | `str` |
| `last_vulnerability_analysis` | `datetime` |
| `last_inherited_risk_score` | `float` |
| `metrics_critical` | `int` |
| `metrics_high` | `int` |
| `metrics_medium` | `int` |
| `metrics_low` | `int` |
| `metrics_unassigned` | `int` |
| `metrics_vulnerabilities` | `int` |
| `metrics_components` | `int` |
| `metrics_vulnerable_components` | `int` |
| `metrics_suppressed` | `int` |
| `metrics_findings_total` | `int` |
| `metrics_findings_audited` | `int` |
| `metrics_policy_violations_total` | `int` |
| `metrics_last_occurrence` | `datetime` |

