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

`vendor_risks` fans a request out per vendor across a thread pool (UpGuard's
`/risks/vendors` sweep is 1–60s per vendor and there can be hundreds of vendors) —
the only posture resource that does concurrent per-parent network calls rather than
sequential pagination. Tune with `collect("vendor_risks", max_workers=8, max_pages=200)`.

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

### Intune and MDE configuration

Both authenticate via Azure AD client-credentials against the tenant's OAuth2 endpoint
(shared internal helper, not vendor SDKs).

| Constructor key | Env var |
|---|---|
| `tenant_id` | `INTUNE_TENANT_ID` / `MDE_TENANT_ID` |
| `client_id` | `INTUNE_CLIENT_ID` / `MDE_CLIENT_ID` |
| `client_secret` | `INTUNE_CLIENT_SECRET` / `MDE_CLIENT_SECRET` |

Neither supports incremental sync (the reference implementations do via `$filter`
checkpoints) — every `collect()` is a full snapshot, per posture's locked snapshot
semantics. `intune`'s `device_configurations` / `device_configuration_detail` only
carry the fields the accelerator explicitly named as aliases, not the full raw Graph
payload it also flattens generically. `mde`'s `machine_vulnerabilities` fans a request
out per machine across a thread pool (up to `max_workers`, default 25) — the same
pattern as UpGuard's `vendor_risks`. `intune`'s `attack_simulation_users` fetches the
targeted-user report for each `attack_simulations` id (one paginated call per
simulation, click/report/training events kept as JSON blobs rather than exploded
into further tables).

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src tests
black src tests
```
