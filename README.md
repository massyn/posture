# posture

Runtime-agnostic Python library for CCM (Continuous Control Monitoring) data collection.
The entire contract: credentials in, DataFrame out. Runs unchanged in Docker, Airflow,
Databricks — the library never knows or cares where it executes.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the design behind this
library — the collect/parse split, locked design decisions, manifest schema, and
per-collector implementation notes.

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
WIZ_CLIENT_ID=xxx
WIZ_CLIENT_SECRET=xxx
WIZ_API_ENDPOINT=https://api.us1.app.wiz.io/graphql
WIZ_TOKEN_URL=https://auth.app.wiz.io/oauth/token  # optional, see below
SAILPOINT_BASE_URL=https://your-tenant.api.identitynow.com
SAILPOINT_CLIENT_ID=xxx
SAILPOINT_CLIENT_SECRET=xxx
SNYK_TOKEN=xxx
SNYK_ENDPOINT=https://api.snyk.io  # optional, see below
DNSIMPLE_TOKEN=xxx
DNSIMPLE_ENDPOINT=https://api.dnsimple.com/v2/  # optional, see below
PHRIENDLY_PHISHING_CLIENT_ID=xxx
PHRIENDLY_PHISHING_CLIENT_SECRET=xxx
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
| `tenablesc` | `vulnerabilities`, `hosts`, `assets`, `asset_ips` |
| `qualys` | `hosts`, `vulnerabilities`, `vulnerability_detections` |
| `wiz` | `cloud_security_issues`, `inventory`, `vulnerabilities` |
| `sailpoint` | `identities`, `accounts`, `access_profiles`, `roles` |
| `appomni` | `monitored_services`, `policies`, `open_policy_issues`, `posture_policies`, `unified_identities` |
| `snyk` | `organizations`, `members`, `projects`, `issues` |
| `cloudflare` | `zones`, `dns_records`, `cdn_protected_domains` |
| `dnsimple` | `domains` |
| `phriendly_phishing` | `trainings`, `clicks` |
| `vanta` | `controls`, `documents`, `frameworks`, `groups`, `integrations`, `monitored_computers`, `people`, `tests`, `vulnerabilities`, `vulnerable_assets`, `vulnerability_remediations` |

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

Tune `vendor_risks` with `collect("vendor_risks", max_workers=8)`, or pass
`min_severity` to filter server-side (see
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#collector-implementation-notes)
for why this one fans out per vendor).

### Jamf configuration

| Constructor key | Env var |
|---|---|
| `url` | `JAMF_URL` |
| `client_id` | `JAMF_CLIENT_ID` |
| `client_secret` | `JAMF_CLIENT_SECRET` |

`computers_inventory_detail` fetches one computer at a time by id, so expect one
request per device on top of the initial listing call. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#collector-implementation-notes) for
which fields are ported.

### Intune, MDE, and Azure Entra configuration

All three authenticate via Azure AD client-credentials against the tenant's OAuth2
endpoint (shared internal helper, not vendor SDKs).

| Constructor key | Env var |
|---|---|
| `tenant_id` | `INTUNE_TENANT_ID` / `MDE_TENANT_ID` / `AZURE_TENANT_ID` |
| `client_id` | `INTUNE_CLIENT_ID` / `MDE_CLIENT_ID` / `AZURE_CLIENT_ID` |
| `client_secret` | `INTUNE_CLIENT_SECRET` / `MDE_CLIENT_SECRET` / `AZURE_CLIENT_SECRET` |

Every `collect()` is a full snapshot — none of the three support incremental sync.
`mde`'s `machine_vulnerabilities` page size is overridable via a `page_size` kwarg.
`azure_entra`'s `signins` takes an optional `days` kwarg (default 180) that narrows
the server-side `$filter` on `createdDateTime` — still a full point-in-time pull,
not a checkpoint. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#collector-implementation-notes) for
endpoint-level detail on all three.

### KnowBe4 configuration

| Constructor key | Env var |
|---|---|
| `token` | `KNOWBE4_TOKEN` |
| `region` | `KNOWBE4_REGION` (optional — `us` or `eu`, defaults to `us`) |

`pst_recipients` (per-recipient phishing test results — delivered/opened/clicked/
reported timestamps) reads PST ids from `psts` internally unless a `pst_ids` kwarg is
given; concurrency defaults to 10 workers, overridable via a `max_workers` kwarg.

### Salesforce configuration

Requires the optional `simple_salesforce` dependency — install with
`pip install "posture[salesforce]"`. Auth is username + password + security token
(no connected app / client id-secret needed).

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
`pip install "posture[tenableio]"`.

| Constructor key | Env var |
|---|---|
| `access_key` | `TENABLEIO_ACCESS_KEY` |
| `secret_key` | `TENABLEIO_SECRET_KEY` |

### Tenable.sc configuration

Requires the optional `pytenable` dependency — install with
`pip install "posture[tenablesc]"`.

| Constructor key | Env var |
|---|---|
| `endpoint` | `TENABLESC_ENDPOINT` |
| `access_key` | `TENABLESC_ACCESS_KEY` |
| `secret_key` | `TENABLESC_SECRET_KEY` |

`vulnerabilities` takes optional `filters` / `tool` kwargs (defaults: exclude
informational severity, last seen in 30 days; `vulndetails` tool). `hosts` and
`asset_ips` are scoped to a named Tenable.sc asset list via an `asset_name`
kwarg (default `"Non Crowdstrike Assets"`). See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#collector-implementation-notes)
for why `asset_ips` isn't a `derived_from` of `assets`.

### Qualys configuration

Auth is HTTP Basic.

| Constructor key | Env var |
|---|---|
| `username` | `QUALYS_USERNAME` |
| `password` | `QUALYS_PASSWORD` |
| `base_url` | `QUALYS_BASE_URL` (required — varies by platform/subscription, e.g. `https://qualysapi.qualys.com` or a `qgN.apps.qualys.com` regional URL) |

`vulnerabilities` here is Qualys' KnowledgeBase (the QID catalogue — severity, CVSS,
CVE), not a per-host finding; `vulnerability_detections` is the per-host one. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#collector-implementation-notes) for
how both are fetched.

### Wiz configuration

| Constructor key | Env var |
|---|---|
| `client_id` | `WIZ_CLIENT_ID` |
| `client_secret` | `WIZ_CLIENT_SECRET` |
| `api_endpoint` | `WIZ_API_ENDPOINT` (required — tenant/region-specific GraphQL endpoint, e.g. `https://api.us1.app.wiz.io/graphql`, shown in your Wiz console under Settings -> API) |
| `token_url` | `WIZ_TOKEN_URL` (optional — defaults to the shared Auth0 endpoint; override if your tenant is provisioned on Cognito, per the console) |

Direct cursor-paginated GraphQL queries (no report-export flow). See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#collector-implementation-notes) for a
caveat on the GraphQL field paths used here.

### SailPoint configuration

| Constructor key | Env var |
|---|---|
| `base_url` | `SAILPOINT_BASE_URL` (required — tenant API URL, e.g. `https://your-tenant.api.identitynow.com`) |
| `client_id` | `SAILPOINT_CLIENT_ID` |
| `client_secret` | `SAILPOINT_CLIENT_SECRET` |

Targets Identity Security Cloud (ISC, the cloud SaaS product formerly known as
IdentityNow) — not IdentityIQ. OAuth2 client-credentials against
`<base_url>/oauth/token`, then offset/limit-paginated REST API v3 calls.

### AppOmni configuration

| Constructor key | Env var |
|---|---|
| `access_token` | `APPOMNI_ACCESS_TOKEN` (static bearer token issued in the AppOmni console) |
| `instance` | `APPOMNI_INSTANCE` (tenant subdomain, e.g. `acme` for `acme.appomni.com`) |

Static bearer token auth (no OAuth flow). `policies` and `posture_policies` hit the
same `/policy/` endpoint with different default filters (reference policies vs.
monitored-service-config policies). See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#collector-implementation-notes) for a
caveat on the manifest field paths used here.

### Snyk configuration

| Constructor key | Env var |
|---|---|
| `token` | `SNYK_TOKEN` |
| `endpoint` | `SNYK_ENDPOINT` (optional — defaults to `https://api.snyk.io`) |

Static token auth (`Authorization: token ...`). `members`, `projects`, and `issues`
have no "all orgs" endpoint, so each fans out per organisation id across a thread
pool — org ids are read from `organizations` internally unless an `org_ids` kwarg is
given; concurrency defaults to 8 workers, overridable via a `max_workers` kwarg. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#collector-implementation-notes) for a
caveat on the manifest field paths used here.

### Cloudflare configuration

| Constructor key | Env var |
|---|---|
| `api_token` | `CLOUDFLARE_API_TOKEN` |

Static API token auth (`Authorization: Bearer ...`), global API base URL (no tenant
subdomain). `dns_records` and `cdn_protected_domains` have no "all zones" endpoint, so
each fans out per zone id across a thread pool — zone ids are read from `zones`
internally unless a `zone_ids` kwarg is given; concurrency defaults to 8 workers,
overridable via a `max_workers` kwarg. `cdn_protected_domains` hits the same
`/zones/{zone_id}/dns_records` endpoint as `dns_records` with `proxied=true` passed
server-side, returning only the records actually routed through Cloudflare's CDN. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#collector-implementation-notes) for a
caveat on the manifest field paths used here.

### DNSimple configuration

| Constructor key | Env var |
|---|---|
| `token` | `DNSIMPLE_TOKEN` |
| `endpoint` | `DNSIMPLE_ENDPOINT` (optional — defaults to `https://api.dnsimple.com/v2/`) |

Static bearer token auth. Every v2 endpoint is scoped under an account id, so
`_authenticate` calls DNSimple's `whoami` once to discover it before the first
request. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#collector-implementation-notes)
for a caveat on the manifest field paths used here.

### PhriendlyPhishing configuration

| Constructor key | Env var |
|---|---|
| `client_id` | `PHRIENDLY_PHISHING_CLIENT_ID` |
| `client_secret` | `PHRIENDLY_PHISHING_CLIENT_SECRET` |

OAuth2 client-credentials against a dedicated auth host
(`auth.api.phriendlyphishing.com`), separate from the API host. `clicks`
defaults its server-side `start_time`/`end_time` range to the trailing 366
days (plus one day forward); pass `start_time`/`end_time` kwargs
(`YYYY-MM-DD`) to override. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#collector-implementation-notes)
for a caveat on the manifest field paths used here.

### Vanta configuration

| Constructor key | Env var |
|---|---|
| `client_id` | `VANTA_CLIENT_ID` |
| `client_secret` | `VANTA_CLIENT_SECRET` |

OAuth2 client-credentials against Vanta's global token host
(`https://api.vanta.com/oauth/token`) — no tenant subdomain or regional
discovery. Every resource is a real top-level paginated endpoint (cursor-based
`pageSize`/`pageCursor`), no fan-out. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#collector-implementation-notes)
for a caveat on the manifest field paths used here.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src tests
black src tests
```
