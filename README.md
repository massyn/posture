# posture

Runtime-agnostic Python library for CCM (Continuous Control Monitoring) data collection.
The entire contract: credentials in, DataFrame out. Runs unchanged in Docker, Airflow,
Databricks — the library never knows or cares where it executes.

## Installation

```bash
pip install posture
```

`posture` loads a `.env` file from the current directory (or a parent) automatically
on import — no code changes needed. Variables already set in the environment always
take precedence over `.env` values.

```
# .env
CROWDSTRIKE_CLIENT_ID=xxx
CROWDSTRIKE_CLIENT_SECRET=xxx
OKTA_DOMAIN=https://your-org.okta.com
OKTA_TOKEN=xxx
WORKSPACEONE_CLIENT_ID=xxx
WORKSPACEONE_CLIENT_SECRET=xxx
WORKSPACEONE_API_SERVER=asXXX.awmdm.com
WORKSPACEONE_TOKEN_URL=https://na.uemauth.workspaceone.com/connect/token  # optional, see below
UPGUARD_API_KEY=xxx
UPGUARD_BASE_URL=https://au.cyber-risk.upguard.com/api/public  # optional, see below
JAMF_URL=https://your-org.jamfcloud.com
JAMF_CLIENT_ID=xxx
JAMF_CLIENT_SECRET=xxx
INTUNE_TENANT_ID=xxx
INTUNE_CLIENT_ID=xxx
INTUNE_CLIENT_SECRET=xxx
MDE_TENANT_ID=xxx
MDE_CLIENT_ID=xxx
MDE_CLIENT_SECRET=xxx
AZURE_TENANT_ID=xxx
AZURE_CLIENT_ID=xxx
AZURE_CLIENT_SECRET=xxx
KNOWBE4_TOKEN=xxx
KNOWBE4_REGION=us  # optional, see below
TENABLEIO_ACCESS_KEY=xxx
TENABLEIO_SECRET_KEY=xxx
SALESFORCE_USERNAME=xxx
SALESFORCE_PASSWORD=xxx
SALESFORCE_TOKEN=xxx
SALESFORCE_DOMAIN=test  # optional, see below
SALESFORCE_SCHEMA_FILE=/path/to/salesforce.json  # optional, see below
QUALYS_USERNAME=xxx
QUALYS_PASSWORD=xxx
QUALYS_BASE_URL=https://qualysapi.qualys.com  # platform URL, varies by subscription
```

## Usage

```python
from posture import CCM

ccm = CCM("crowdstrike")                          # creds from CROWDSTRIKE_* env vars
ccm = CCM("crowdstrike", {"client_id": "xxx"})    # partial override, rest from env

df = ccm.collect("hosts")                          # always a complete pandas DataFrame
ccm.flush_cache()                                  # the only cache invalidation
```

`collect()` always returns a complete `pandas.DataFrame` for the requested resource, or
raises — there is no such thing as a partial snapshot in this library.

### Discovering what's available

```python
from posture import catalog

catalog()
# {
#   "crowdstrike": {
#     "required_config": {"client_id": "CROWDSTRIKE_CLIENT_ID", "client_secret": "CROWDSTRIKE_CLIENT_SECRET"},
#     "resources": {
#       "hosts": {"derived_from": None, "columns": ["client_id", "device_id", ...]},
#       "vulnerability_remediations": {"derived_from": "vulnerabilities", "columns": [...]},
#       ...
#     },
#   },
#   "knowbe4": {...},
#   ...
# }
```

`catalog()` never instantiates a collector, never touches the network, and needs no
credentials — it reads sources, required config (as constructor key → env var), and
resources (including which are derived, and their declared columns) straight off the
registered `Collector` classes. It only reports *required* config — optional knobs
(e.g. `region`, `base_url`) aren't tracked as data, so check a source's section below
for those.

## Example: export Crowdstrike hosts to local JSON

```python
import json
from pathlib import Path

from posture import CCM

# CROWDSTRIKE_CLIENT_ID / CROWDSTRIKE_CLIENT_SECRET must be set in the environment
ccm = CCM("crowdstrike")
df = ccm.collect("hosts")

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

output_path = output_dir / "hosts.json"
output_path.write_text(df.to_json(orient="records", date_format="iso", indent=2))

print(f"Wrote {len(df)} hosts to {output_path}")
```

## Supported sources

| Source | Resources |
|---|---|
| `crowdstrike` | `hosts`, `vulnerabilities`, `vulnerability_remediations`, `zero_trust_assessment`, `zero_trust_assessment_os_signals`, `zero_trust_assessment_sensor_signals` |
| `okta` | `users`, `devices`, `device_users` |
| `workspaceone` | `computers` |
| `upguard` | `vendors`, `domains`, `breached_identities`, `organisation`, `vendor_risks` |
| `jamf` | `computers_inventory`, `computers_inventory_detail`, `mobile_devices`, `policies`, `categories`, `buildings`, `departments` |
| `intune` | `managed_devices`, `users`, `device_configurations`, `managed_device_detail`, `device_configuration_detail`, `device_compliance_policies`, `attack_simulations`, `attack_simulation_users` |
| `mde` | `machines`, `vulnerabilities`, `device_av_info`, `machine_vulnerabilities` |
| `azure_entra` | `users`, `signins`, `audit_logs` |
| `knowbe4` | `training_enrollments`, `psts`, `pst_recipients` |
| `salesforce` | one per object declared in `salesforce.json` (default: `fixed_asset__c`, `krow__location__c`, `krow__project_resources__c`, `domain__c`, `krow__team__c`) |
| `tenableio` | `assets`, `vulnerabilities` |
| `qualys` | `hosts`, `vulnerabilities`, `vulnerability_detections` |

### Crowdstrike configuration

| Constructor key | Env var |
|---|---|
| `client_id` | `CROWDSTRIKE_CLIENT_ID` |
| `client_secret` | `CROWDSTRIKE_CLIENT_SECRET` |

### Okta configuration

| Constructor key | Env var |
|---|---|
| `domain` | `OKTA_DOMAIN` |
| `token` | `OKTA_TOKEN` |

### Workspace ONE configuration

| Constructor key | Env var |
|---|---|
| `client_id` | `WORKSPACEONE_CLIENT_ID` |
| `client_secret` | `WORKSPACEONE_CLIENT_SECRET` |
| `api_server` | `WORKSPACEONE_API_SERVER` |
| `token_url` | `WORKSPACEONE_TOKEN_URL` (optional — defaults to the APAC realm; set explicitly if your tenant is NA or EMEA, since there's no reliable way to derive the realm from `api_server`) |

### UpGuard configuration

| Constructor key | Env var |
|---|---|
| `api_key` | `UPGUARD_API_KEY` |
| `base_url` | `UPGUARD_BASE_URL` (optional — defaults to the AU tenant) |

`vendor_risks` fans a single (unpaginated — UpGuard's `/risks/vendors` has no
pagination) request out per vendor across a thread pool (1–60s per vendor and
there can be hundreds of vendors) — the only posture resource that does
concurrent per-parent network calls rather than sequential pagination. Tune
with `collect("vendor_risks", max_workers=8)`, or pass `min_severity` to filter
server-side.

### Jamf configuration

| Constructor key | Env var |
|---|---|
| `url` | `JAMF_URL` |
| `client_id` | `JAMF_CLIENT_ID` |
| `client_secret` | `JAMF_CLIENT_SECRET` |

Only the fields the accelerator explicitly renamed are ported for `computers_inventory`,
`computers_inventory_detail`, and `mobile_devices` — the reference implementation
passes the rest of each response through via generic flattening, which posture's
allowlist-only manifest doesn't support. `computers_inventory_detail` fetches one
computer at a time by id (from `computers_inventory`), same pattern as Okta's
`device_users`.

### Intune, MDE, and Azure Entra configuration

All three authenticate via Azure AD client-credentials against the tenant's OAuth2
endpoint (shared internal helper, not vendor SDKs).

| Constructor key | Env var |
|---|---|
| `tenant_id` | `INTUNE_TENANT_ID` / `MDE_TENANT_ID` / `AZURE_TENANT_ID` |
| `client_id` | `INTUNE_CLIENT_ID` / `MDE_CLIENT_ID` / `AZURE_CLIENT_ID` |
| `client_secret` | `INTUNE_CLIENT_SECRET` / `MDE_CLIENT_SECRET` / `AZURE_CLIENT_SECRET` |

None support incremental sync (the reference implementations do via `$filter`
checkpoints) — every `collect()` is a full snapshot, per posture's locked snapshot
semantics. `intune`'s `device_configurations` / `device_configuration_detail` only
carry the fields the accelerator explicitly named as aliases, not the full raw Graph
payload it also flattens generically. `mde`'s `machine_vulnerabilities` fans a request
out per machine across a thread pool (up to `max_workers`, default 25) — the same
pattern as UpGuard's `vendor_risks`. `intune`'s `attack_simulation_users` fetches the
targeted-user report for each `attack_simulations` id (one paginated call per
simulation, click/report/training events kept as JSON blobs rather than exploded
into further tables). `azure_entra`'s `signins` takes an optional `days` kwarg
(default 180) that narrows the server-side `$filter` on `createdDateTime` — still a
full point-in-time pull, not a checkpoint.

### KnowBe4 configuration

| Constructor key | Env var |
|---|---|
| `token` | `KNOWBE4_TOKEN` |
| `region` | `KNOWBE4_REGION` (optional — `us` or `eu`, defaults to `us`) |

`pst_recipients` (per-recipient phishing test results — delivered/opened/clicked/
reported timestamps) fans out one paginated call per PST id across a bounded thread
pool, mirroring `mde`'s `machine_vulnerabilities`. PST ids are read from `psts`
internally unless a `pst_ids` kwarg is given; concurrency defaults to 10 workers,
overridable via a `max_workers` kwarg.

### Salesforce configuration

Requires the optional `simple_salesforce` dependency — install with
`pip install "posture[salesforce]"`. Auth is username + password + security
token (no connected app / client id-secret needed) — the alternative would be
hand-rolling Salesforce's SOAP login flow, so this is an approved vendor-SDK
exception alongside `pytenable`.

| Constructor key | Env var |
|---|---|
| `username` | `SALESFORCE_USERNAME` |
| `password` | `SALESFORCE_PASSWORD` |
| `token` | `SALESFORCE_TOKEN` |
| `domain` | `SALESFORCE_DOMAIN` (optional — omit for production, `"test"` for a sandbox, or a custom My Domain) |
| `schema_file` | `SALESFORCE_SCHEMA_FILE` (optional — path to a JSON file overriding the shipped `salesforce.json`) |

Resources aren't hand-written per endpoint: `salesforce.json` declares one entry
per Salesforce object as a flat `{field_name: type}` map, and both the SOQL
query and the manifest are generated from that file. Add an object by editing
the JSON (or pointing `schema_file` at your own), not by changing collector code.

### Tenable.io configuration

Requires the optional `pytenable` dependency — install with
`pip install "posture[tenableio]"`. `pytenable`'s export jobs are bespoke
server-side machinery (polling, chunking) that the base class's generic REST
pagination scaffold can't express, so this collector is one of the two approved
vendor-SDK exceptions (alongside `simple_salesforce`).

| Constructor key | Env var |
|---|---|
| `access_key` | `TENABLEIO_ACCESS_KEY` |
| `secret_key` | `TENABLEIO_SECRET_KEY` |

### Qualys configuration

Raw `requests` against the Qualys API v2 (`/api/2.0/fo/...`), which returns XML rather
than JSON — the collector converts each response into plain dicts at fetch time, so
`parse.py` never has to know XML exists. Auth is HTTP Basic; pagination follows the
full next-page URL Qualys returns in a truncated response rather than a token.

| Constructor key | Env var |
|---|---|
| `username` | `QUALYS_USERNAME` |
| `password` | `QUALYS_PASSWORD` |
| `base_url` | `QUALYS_BASE_URL` (required — varies by platform/subscription, e.g. `https://qualysapi.qualys.com` or a `qgN.apps.qualys.com` regional URL) |

`vulnerability_detections` is derived from the per-host detection list (fetched
internally as `host_detections`) — one row per (host, QID), mirroring the
`vulnerabilities` / `vulnerability_remediations` shape in `crowdstrike`. `vulnerabilities`
here is Qualys' KnowledgeBase (the QID catalogue — severity, CVSS, CVE), not a
per-host finding.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src tests
black src tests
```
