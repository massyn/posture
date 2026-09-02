# posture — architecture and design notes

Runtime-agnostic Python library for CCM (Continuous Control Monitoring) data collection.
The entire contract: **credentials in, DataFrame out.** Runs unchanged in Docker, Airflow,
Databricks — the library never knows or cares where it executes.

```python
from posture import CCM

ccm = CCM("crowdstrike")                          # creds from CROWDSTRIKE_* env vars
ccm = CCM("crowdstrike", {"client_id": "xxx"})    # partial override, rest from env

df = ccm.collect("hosts")                          # always a complete pandas DataFrame
df = ccm.collect("vulnerabilities", filter="status:'open'")   # vendor-dialect kwargs
df = ccm.collect("vulnerabilities", facet=["cve"])  # trim payload: CVE fields only, no remediation
df = ccm.collect("vulnerability_remediations")     # derived resource — no second API call
ccm.flush_cache()                                  # the only cache invalidation

for df in ccm.collect_page("machine_vulnerabilities"):  # one DataFrame per API page
    ...                                                  # bounded memory for large resources
```

This document is the canonical reference for the library's design: the collect/parse
split, the manifest schema, locked design decisions, and the conventions a new collector
must follow. It's aimed at anyone contributing a collector or reviewing one — no
tool-specific context required.

## Architecture: two phases, hard boundary

```
collect(resource, **kwargs)   # NETWORK: auth, token refresh, endpoint calls, pagination
parse(raw, manifest)          # PURE: flatten, type coercion, derived explosion → df
```

- `collect` owns everything that touches the network, **including pagination** (pagination
  is more HTTP calls; it can never live in parse).
- `parse` is a pure function: raw records + manifest in, df out. No network, no state,
  no side effects. It must be fully testable with fixture JSON and zero mocked HTTP.

## Repo layout (src layout, deliberately)

```
src/posture/
├── __init__.py         # exports CCM + exceptions
├── exceptions.py       # taxonomy below — smallest file, biggest contract
├── base.py             # Collector ABC: session, retry/refresh, pagination scaffold, cache
├── parse.py            # manifest engine, flattener, six types, datetime cascade, derived explosion
└── collectors/
    └── crowdstrike.py  # fetch() + resource manifests — target ~100 lines
tests/
├── fixtures/crowdstrike/   # sanitised real API responses, including ugly cases
├── test_parse.py           # runs entirely offline — most of the suite lives here
└── test_redaction.py       # secrets never appear in logs at ANY level — enforced by test
```

## Locked design decisions — do not relitigate

1. **One instance per source.** Instance = authenticated session = one point-in-time
   snapshot. Multi-tenant = two instances.
2. **Config resolution:** explicit constructor dict beats env vars, per key. Validate
   config at construction (fail fast, name the env var checked); authenticate lazily on
   first call. `__repr__` redacts secrets (Databricks notebooks auto-repr).
3. **`collect()` returns a complete pandas df, always; `collect_page()` returns one df
   per API page, for resources too large to hold in memory at once.** Pagination is
   internal and invisible to `collect()`; `collect_page()` is the one place it's exposed,
   deliberately, as `for df in ccm.collect_page(resource)`. Both share the same
   all-or-nothing guarantee: if the pull dies mid-pagination after retries, raise
   `IncompleteCollection` — `collect()` returns nothing, and `collect_page()`'s generator
   raises out of the loop the caller is iterating, before any page is treated as final.
   Partial data does not exist in this library's vocabulary — a partial snapshot presented
   as complete is a compliance lie. `collect()` is a thin wrapper: `pd.concat(list(
   collect_page(...)))`.
4. **kwargs = vendor query dialect** (FQL for Crowdstrike). Always optional — bare
   `collect(resource)` must work. Unknown kwargs raise. Never invent a unified
   cross-vendor filter language. Default filters live in the resource definition.
   Where a collector merges kwargs onto its own default params for the same endpoint,
   kwargs must win — an operator overriding a built-in default is expected, not an edge case.
5. **Credentials never travel through kwargs.** Constructor = "who am I";
   kwargs = "what data do I want".
6. **Snapshot semantics.** Full pull, point in time. No incremental sync, ever.
7. **Token refresh mid-run is a base-class concern.** Crowdstrike OAuth tokens live
   ~30 min; pulls can run hours. Re-auth on 401 / proactive refresh inside the pagination
   loop, at the request level. Retry at request level only — never restart a stream
   that has already yielded.
8. **Transient connection errors are retried, not fatal.** `ConnectionError`,
   `Timeout`, and `ChunkedEncodingError` get up to 2 retries with a fixed 5s wait,
   at the request level, in the base class — a network blip must not kill an
   otherwise-healthy collection. Retries exhausted → the underlying exception
   propagates and is wrapped as `IncompleteCollection` same as any other failure.
   This budget is fixed and shared by every collector — if a specific endpoint's
   response is simply slow (a large unpaginated payload, for example), the fix is a
   longer per-request timeout for that endpoint, not a bigger retry budget.
9. **Session cache:** a resource's raw records are cached only when another resource's
   manifest declares `derived_from` or `requires` it — everything else streams straight
   from fetch through `parse()`, page by page, and is never cached or held as a whole.
   A cached resource is disk-backed (see `posture/_spill.py`), keyed by
   (resource, frozen kwargs), and replayed back in bounded batches — never as one
   in-memory list, however large the resource. Retained for instance lifetime; NO TTL,
   no cache config. `flush_cache()` is the only invalidation.
10. **Raw `requests` for Crowdstrike — no FalconPy.** Rule: vendor SDKs only when the API
    has bespoke machinery the base class can't generalise (pyTenable's export jobs
    qualify, later, as an extra). Crowdstrike is generic REST — that pattern is the
    base class's job.

## Schema: declared manifest per resource (allowlist, not flattener)

```python
"hosts": {
    "endpoint": "...",
    "columns": {
        "device_id":  ("device_id", "str"),
        "last_seen":  ("last_seen", "datetime"),
        "tags":       ("tags", "json"),
        "policy_id":  ("device_policies.prevention.policy_id", "str"),
    },
},
"vulnerability_remediations": {
    "derived_from": "vulnerabilities",
    "record_path": "remediation.entities",
    "columns": {
        "vulnerability_id": ("$parent.id", "str"),
        "remediation_id":   ("id", "str"),
    },
},
```

- Column name → (dotted JSON path, type, optional hints dict). parse plucks named
  leaves — never generic flattening, never dict-valued columns.
- **Six types only:** `str`, `int`, `float`, `bool`, `datetime`, `json`. Nothing else.
- Lists of scalars → JSON string in the cell. Lists of objects → derived resource with
  its own grain and a `$parent.` FK. Grain is sacred: one row per host means one row
  per host.
- Empty results return the full declared column set, zero rows.
- The manifest is executable documentation: `ccm.schema("hosts")` returns it.
- Allowlist ≠ normalisation: raw vendor field names and semantics. Interpretation
  belongs to the downstream SQL layer, never here.

## Datetime policy

- **Every date a vendor gives us becomes a real datetime. No exceptions.** A
  collector that leaves a known-format date field typed `str` because the format
  is inconvenient (ambiguous, non-ISO, whatever) has not implemented the
  contract — it's implemented a partial one and left the parsing as the
  caller's problem. Type it `datetime` and give `parse.py` what it needs
  (a `format` hint) to parse it correctly. This was gotten wrong once already
  (`precise.py`'s day-first `valid_from`/`valid_to` were shipped as `str` to
  dodge an ambiguous-date bug — the bug was in `parse.py`'s hint priority, not
  a reason to abandon typing the column correctly) — don't repeat it.
- ONE parse function handles all datetime parsing. Output is always tz-aware UTC
  (`datetime64[us, UTC]`) — never naive. Localisation is the consumer's problem.
  Microsecond precision matches Arrow/Parquet/BigQuery/Snowflake defaults, avoiding
  unsafe-cast failures downstream on values with no genuine sub-microsecond precision.
- Cascade: epoch by magnitude (10 digits = s, 13 = ms, 16 = µs) → explicit `format`
  hint from the manifest, when the column declares one → ISO 8601 family otherwise.
  A `format` hint is authoritative, not a last-resort fallback: a collector only
  declares one because the field's format is otherwise ambiguous (e.g. day-first
  `DD/MM/YYYY`, indistinguishable from month-first for any date where both
  components are ≤12) — the generic ISO parser would happily "succeed" on such a
  value, just silently wrong (day/month swapped), so it must never get first
  refusal at parsing it. Naked timestamps assumed UTC.
- Unparseable → `NaT` + a warning carrying resource, column, sample value, count.
  Never raise mid-collection over a bad value; never pass strings through into a
  datetime column. Same coercion policy for bool and numerics.
- Bool exception: `true`/`false`/`unknown` (case-insensitive) are all valid inputs.
  Some vendors (e.g. MDE's `avIs*UpToDate` fields) report a genuine tri-state — the
  device hasn't reported that status yet — not a malformed value. `"unknown"` coerces
  to `None` silently, no warning; only values outside all three states warn.

## Performance: per-item fan-out

Some resources require one network call per item rather than one paginated call per
resource — Intune's `managed_device_detail`, `device_configuration_detail`, and
`attack_simulation_users` are reference cases (a detail lookup per device id, a
per-simulation user-report drain). Run at a real tenant's scale, a serial `for` loop
over these is the dominant cost of the whole collection, and — because these
resources have no cursor to resume from, unlike ordinary pagination — a mid-run
failure used to discard every already-fetched item and restart the entire fan-out
from zero on retry. A live Intune incident (25k+ devices, a token expiring ~71
minutes into the fan-out) turned an 85-minute run into one that re-fetched 6,801
already-completed devices on top of the rest. This is now fixed at the base-class
level; every collector doing per-item fan-out **must** use it.

- Fan out via `Collector._resumable_fanout(resource, ids, fetch_one, max_workers)`
  (`base.py`) rather than hand-rolling a `ThreadPoolExecutor` — it is the base-class
  primitive for this shape, promoted there after the same discard-on-retry bug was
  found independently in eight collectors (intune, github, okta, cloudflare, snyk,
  upguard, whistic, appomni, knowbe4 — effectively every fan-out in the codebase).
  It persists per-resource progress (`self._fanout_progress[resource] = {id:
  result}`) across retries of the same `_fetch_page` call: a mid-run exception
  (token expiry, a transient connection error) leaves already-completed ids intact,
  so a retry only re-fetches what's missing instead of starting over. `None` is a
  valid completed result (e.g. a 404 treated as confirmed-missing), not re-fetched
  on retry. `fetch_one` may return a single record or a list of records (for an id
  whose own fetch is itself paginated, e.g. `attack_simulation_users`) — both are
  flattened into the returned list. Progress is cleared automatically once a fan-out
  completes successfully, so it never leaks into an unrelated later call. Worker
  count is still a module constant per collector (the `max_workers` parameter),
  since the right ceiling depends on the vendor's own throttling — 10 in
  `intune.py` (`_MAX_FANOUT_WORKERS`), 5 in `okta.py` (tighter limits), etc.
- `_resumable_fanout` does not fit every shape verbatim — if `fetch_one` needs to
  return something other than a record/list/None (e.g. UpGuard's
  `_fetch_risks_for_hostname`, which returns a `(records, truncated)` tuple to
  support per-vendor truncation tracking and progress logging), hand-roll the same
  pattern directly against `self._fanout_progress[resource]` rather than forcing
  the shape through the helper or reverting to a plain, non-resumable
  `ThreadPoolExecutor`. See `upguard.py::_fetch_vendor_risks_page` for the
  reference shape: skip ids already in progress, write into progress as each
  future completes (not batched into a local list only assembled at the end),
  cancel pending futures and re-raise on `except BaseException`, clear progress on
  success.
- `Collector.__init__` mounts an `HTTPAdapter(pool_maxsize=_HTTP_POOL_MAXSIZE)` on
  the shared session (`base.py`) so concurrent requests from one collector don't
  starve urllib3's connection pool. `_HTTP_POOL_MAXSIZE` must stay >= the largest
  fan-out worker count across all collectors — bump it whenever a collector's
  fan-out width outgrows it.
- `requests.Session` is safe to share across threads for making calls — no lock
  needed around `self._session.get(...)`. Do NOT add locking there.
- Retry/re-auth still stays outside the fan-out: `_request_with_retry` in `base.py`
  wraps the *whole* `_fetch_page` call, so a 401/429 raised by any worker propagates
  up and the entire `_fetch_page` call is retried as one unit — but as of
  `_resumable_fanout`, that retry now skips ids already completed rather than
  re-fetching everything. Do not add per-worker retry beyond what a vendor's own
  local backoff needs (e.g. `okta.py`'s per-parent 429 handling in `_drain_scoped`)
  — auth refresh and outer rate-limit handling stay single-threaded in the base
  class.
- New collectors that need this shape use `_resumable_fanout` directly — it is a
  base-class primitive now, not something to reintroduce as a fresh
  `ThreadPoolExecutor` per collector (the anti-overfitting rule no longer applies
  here; this was already promoted after the second, third, ... collector
  demonstrated the identical need).

### URL/endpoint config is normalized, never trusted raw

Any collector whose config includes an operator-supplied base URL/endpoint
(Tenable.sc's `endpoint`, Wiz's `api_endpoint`, SailPoint's `base_url`,
DNSimple's `endpoint`) must declare that key in `url_config_keys` on the
collector class. `Collector._resolve_config` (`base.py`) normalizes every
key listed there through `_normalize_url`: a bare host
(`host.example.com`) and a full URL (`https://host.example.com/`) both
collapse to the same shape — explicit `https://`, no trailing slash.
Operators shouldn't have to know which vendor's docs show the scheme and
which don't, and the collector shouldn't guess at request time. `config_keys`
(`base.py`) maps every key a collector accepts to whether it's required —
`{"token": True, "endpoint": False}` — and `catalog()`/the generated docs
read this map directly, so an optional key (e.g. DNSimple's `endpoint`,
which has a default rather than being required) is still documented instead
of being invisible. Resolving an optional key via a raw `os.environ.get(...)`
call in a collector's own `__init__` instead of listing it in `config_keys`
defeats that — don't do it. A key with a default that still needs
normalizing (DNSimple's `endpoint`) applies `self._normalize_url(...)`
explicitly at the point it's set in an overridden `_resolve_config`, since
the generic `url_config_keys` loop only normalizes keys already present in
the resolved config. Because normalization always strips the trailing
slash, path-joining call sites must supply their own separator
(`f"{self._base_url}/{path}"`), not raw concatenation.

### Collector `__init__` overrides must forward `record_limit`

`Collector.__init__` (`base.py`) takes `config` and a keyword-only `record_limit:
int | None = None`, and `CCM()` (`src/posture/__init__.py`) always passes
`record_limit` through to the constructor. Any collector that overrides `__init__`
(to set up a base URL, region, cache, etc.) MUST repeat both parameters and forward
`record_limit` to `super().__init__()`:

```python
def __init__(
    self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
) -> None:
    super().__init__(config, record_limit=record_limit)
    ...
```

Omitting `record_limit` from the override's signature doesn't silently no-op it —
`CCM()` calls every collector with `record_limit` as a keyword argument, so a
collector whose `__init__` doesn't accept it fails with `TypeError: unexpected
keyword argument 'record_limit'` the moment it's constructed. This has bitten every
collector in the codebase at once before (each one independently overrides
`__init__`, so the base class can't enforce it) — when adding a new collector, copy
the signature above rather than the older `def __init__(self, config: dict[str, Any]
| None = None) -> None:` shape still visible in some diffs/history.

- **SentinelOne** — Singularity Platform EDR/XDR, raw `requests` against the
  tenant-scoped Management API (`https://<console>.sentinelone.net/web/api/v2.1`),
  no vendor SDK. Auth is a static API token (`Authorization: ApiToken
  <token>`), same "just set the header" shape as AppOmni/Snyk/UpGuard, but
  the token inherits the generating user's own role/scope rather than
  being independently scoped at creation — the read-only shape is
  "provision a dedicated, minimally-privileged viewer user, then generate
  that user's token." `console_url` is required config, no cross-tenant
  discovery, same shape as Wiz's `api_endpoint`. Pagination is one cursor
  shape shared by every list endpoint (`{"pagination": {"nextCursor"},
  "data": [...]}`) — simpler than most collectors here, one `_fetch_page`
  implementation serves every resource keyed only by endpoint path.
  `threats` and `alerts` deliberately overlap (older endpoint-threat model
  vs. newer unified XDR alert model) — both are included per explicit
  instruction rather than picking one, to be revisited once verified
  against a real tenant which one a given console actually populates.
  `installed_applications` hits an already-paginated top-level endpoint
  (filterable by `agentUuid`), not a per-agent fan-out — unlike Jamf's/
  Intune's per-device detail calls. Deliberately out of scope: SentinelOne's
  per-app CVE feed (`application-risks`, under the separately-licensed
  Singularity Ranger Insights module — same reasoning that splits
  CrowdStrike Falcon Cloud Security into `crowdstrike_cspm.py`) and every
  response-action surface (agent disconnect/shutdown/uninstall, remote
  script execution, STAR rules, blocklist management) — read-only
  collection only.
  **Caveat:** `MANIFEST` column paths were built from SentinelOne's public
  API reference and third-party connectors (Cortex XSOAR, Brinqa, Vulcan
  Cyber), not a live schema introspection — same caveat tier as `wiz.py`,
  `appomni.py`, `kandji.py`, and others above. `agents`/`threats` are
  well-corroborated across multiple independent sources; `alerts`,
  `sites`, and `groups` are lower confidence — verify field names/nesting
  against a real tenant's response before relying on this collector,
  particularly for `alerts`.

## Credentials documentation

A collector's `MANIFEST`/`config_keys` document *what* config it needs;
they say nothing about *how* a technical team actually provisions a
read-only credential for it in the vendor's own admin console — a distinct
audience (whoever runs the source system, not whoever runs posture) with a
distinct need (click-by-click steps, not env var names). Every collector
**must** have a hand-written `docs/credentials/<source>.md` — `<source>`
matching its registered name in `_SOURCES` (`src/posture/__init__.py`), the
same name `catalog()`/`docs/collectors/<source>.md` use. These are prose
runbooks, not generated: unlike `docs/index.md`/`docs/collectors/*.md`
(built from `catalog()` by `scripts/build_schema.py` — see "Regenerate
collector docs" in `CLAUDE.md`), there is no programmatic source of truth
for "which button to click in the Jamf console," so these are written and
maintained by hand.

Shape, established by the first batch of these pages (crowdstrike,
crowdstrike_cspm, jamf, servicenow, qualys, intune, mde):

- A back-link to the collector's generated doc page
  (`[← back to collector docs](../collectors/<source>.md)`).
- Numbered/bulleted steps through the vendor's admin console to create a
  dedicated, minimally-scoped (read-only wherever the vendor's own role
  model allows it) service identity — API client, service account, or app
  registration — naming it consistently (`CCM - Read Only`) so an auditor
  can recognise the same convention across vendors.
- A **Record the credentials** section as a table mapping each value to
  the exact collector config key and environment variable
  (`env_prefix` + `_` + key, upper-cased) it resolves to, so there is no
  translation step between "what the vendor console shows you" and "what
  you paste into config/`.env`."
- Where a vendor's own permission model has no read-only variant for some
  capability (e.g. MDE's `Alert.ReadWrite.All` — Microsoft provides no
  read-only alerts scope), that's called out explicitly rather than left
  looking like an oversight.
- Where multiple collectors share one underlying identity (Intune and MDE
  share one Azure AD app registration via `_azure_oauth.py`), each
  collector still gets its own self-contained page — a team standing up
  just one of the two shouldn't have to read the other's doc — but each
  cross-references the other for the "provision one identity for both"
  shortcut, and each permission table only lists the scopes that
  collector's own resources need.

`scripts/build_schema.py` checks `docs/credentials/<source>.md` for every
registered source while generating docs: when the file exists, the
generated `docs/index.md` entry gets a direct "Credentials" link straight
to it, alongside the link to `docs/collectors/<source>.md`. That's the one
place it's linked from — `docs/collectors/<source>.md` (the generated
schema/env-var page) deliberately does not repeat it, since anyone landing
there arrived from the index and already saw it. When the credentials doc
doesn't exist (not every collector has one yet), the index entry just omits
that link — a missing credentials doc is a documentation gap, never a
build failure. Do not fabricate a
credentials page's steps from guesswork the way `MANIFEST` caveats
elsewhere in this file are sometimes tolerated (built from public docs, not
live-verified) — a wrong click-path is actively misleading to someone
provisioning real production access, worse than no page at all. Skip the
page (leaving the collector unlinked) rather than invent one, until someone
who actually knows the vendor's console (or a v3+ pass over its own admin
API docs) can write it accurately.

## Observability

- **Exceptions** (`exceptions.py`): `AuthenticationError`, `RateLimitExhausted`,
  `ResourceUnknown`, `IncompleteCollection`. Each carries structured attributes
  (`source`, `resource`, `hint`, `records_so_far` where relevant) — wrapper scripts
  compose alerts from fields, never by parsing message strings. The library NEVER
  sends alerts (no Slack/webhook/email code, ever) — it provides the alerting surface.
  All exceptions propagate; never swallow and continue.
- **Logging:** stdlib `logging`, logger per module (`posture.crowdstrike`), the library
  installs a `NullHandler` and never configures handlers. Consistent fields: source,
  resource, pages, records, retry events, elapsed. **Secrets never appear at any log
  level including DEBUG — enforced by test_redaction.py.**
- **Collection report:** `ccm.report(resource)` → records fetched, pages, retries,
  429s honoured, NaT/coercion-warning counts, duration, collected_at. Every df also
  carries a `_collected_at` tz-aware UTC column.
- **Rate limiting:** reactive 429 + `Retry-After` at request level, plus proactive
  pacing off `X-RateLimit-Remaining` headers. Exponential backoff when no `Retry-After`
  is given, capped at 60s per attempt.

## Guardrails

- **Anti-overfitting:** anything vendor-specific stays in that vendor's
  `collectors/<vendor>.py` even when it feels general. Promote to `base.py` only when a
  second collector demonstrably needs it. Mark candidates:
  `# CANDIDATE: promote if <vendor> needs this`.
- **Crowdstrike cloud region auto-discovery:** never hardcode a tenant's region.
  Always authenticate against `api.crowdstrike.com/oauth2/token` first; read the
  `X-Cs-Region` header on that response and route every subsequent call to the
  matching regional base URL (`us-1`/`us-2`/`eu-1`/`us-gov-1`). Mirrors FalconPy's
  behaviour. A hardcoded `us-1` base URL will silently 401 on non-us-1 tenants even
  though auth itself succeeds — this bit us once already.
- **Dependencies:** core = `requests` + `pandas` + `python-dotenv` only. No new
  dependencies without explicit approval. Future vendor SDKs and storage backends ship
  as optional extras. `.env` loading is part and parcel of the library, not optional:
  `posture` calls `load_dotenv()` unconditionally at import time. It never overrides
  variables already set in the environment.
- **Out of scope for v1 — do not build:** Store/storage backends, TTLs or cache
  configuration, incremental sync, alert delivery, per-collector pip packages,
  unified filter languages. (`collect_page()` — see locked decision #3 — shipped;
  it's the deferred `stream()` mentioned in earlier versions of this doc.)
- Production-ready code only. No placeholder code, no speculative syntax, no TODO-stubs
  that would break at runtime.
- Python 3.10+. Type hints throughout. pytest. Keep it simple — this library is five
  files on purpose; every rejected feature is a file that doesn't exist.

## Collector implementation notes

Per-source rationale and mechanics that don't belong in the user-facing README —
why something is built the way it is, not how to configure or call it.

- **Crowdstrike** — cloud-region auto-discovery is covered under Guardrails above.
  `host_groups` hits the combined endpoint (`/devices/combined/host-groups/v1`)
  directly — group entities come back in one paginated call, offset/limit like
  `_query_device_ids`, with no separate query-then-entities round trip (unlike
  `hosts` and `zero_trust_assessment`, which query device ids first and batch-fetch
  entities against them).
- **Crowdstrike CSPM** — Falcon Cloud Security (Horizon), a distinct product
  surface from Falcon endpoint protection with its own OAuth2 client/scopes,
  hence a separate collector (`env_prefix = "CROWDSTRIKE_CSPM"`) rather than
  extending `crowdstrike.py`. Auth and cloud-region discovery (`X-Cs-Region`)
  mirror `crowdstrike.py` exactly — flagged as a `# CANDIDATE` for promotion
  to `base.py` rather than promoted now, per the anti-overfitting rule.
  `iom` and `cloud_asset_inventory` follow the same
  query-ids-then-fetch-entities shape as Falcon's `hosts`/`zero_trust_assessment`
  (both entities endpoints cap at 100 ids per request, unlike Falcon's,
  so their query-page size is capped to match via `_ENTITIES_PAGE_LIMIT`). The
  originally planned `ioa` resource was dropped and replaced with
  `cloud_risks`: CrowdStrike deprecated the standalone cloud
  `/detects/*/ioa/*` endpoints, and the current API reference has no
  confirmed direct successor for per-detection cloud IOA data —
  `cloud_risks` (`/cloud-security-risks/combined/cloud-risks/v1`, a single
  paginated combined-entities call, no separate query step) is the closest
  current equivalent, covering both misconfiguration and attack-path risk
  findings. Verified during initial live testing: the OAuth2 token endpoint
  returns `201 Created` on success, not `200` — the auth status check in
  both `crowdstrike.py` and `crowdstrike_cspm.py` accounts for this.
  **Caveat:** `MANIFEST` column paths were built from CrowdStrike's public
  Falcon Cloud Security API reference, not a live schema introspection —
  same caveat as `wiz.py`, `appomni.py`, `snyk.py`, `cloudflare.py`,
  `dnsimple.py`, `phriendly_phishing.py`, and `vanta.py`. Verify field
  names/nesting against a real tenant's response before relying on this
  collector.
- **Jamf** — only the fields the accelerator explicitly renamed are ported for
  `computers_inventory`, `computers_inventory_detail`, and `mobile_devices`. The
  reference implementation passes the rest of each response through via generic
  flattening, which posture's allowlist-only manifest doesn't support.
  `computers_inventory_detail` fetches one computer at a time by id (from
  `computers_inventory`), the same pattern as Okta's `device_users`.
- **Intune / MDE / Azure Entra** — all three authenticate via Azure AD
  client-credentials against the tenant's OAuth2 endpoint through a shared internal
  helper, not vendor SDKs. None support incremental sync (the reference
  implementations do, via `$filter` checkpoints) — every `collect()` is a full
  snapshot, per the locked snapshot-semantics decision. `intune`'s
  `device_configurations` / `device_configuration_detail` only carry the fields the
  accelerator explicitly named as aliases, not the full raw Graph payload it also
  flattens generically. `mde`'s `machine_vulnerabilities` uses MDE's bulk export
  endpoint (`/api/machines/SoftwareVulnerabilitiesByMachine`, `@odata.nextLink`
  pagination) rather than a per-machine fan-out — one call returns every device's
  vulnerabilities. `intune`'s `attack_simulation_users` fetches the targeted-user
  report for each `attack_simulations` id (one paginated call per simulation,
  click/report/training events kept as JSON blobs rather than exploded into further
  tables).
- **UpGuard** — `vendor_risks` fans a single (unpaginated — UpGuard's
  `/risks/vendors` has no pagination) request out per vendor across a thread pool
  (1–60s per vendor, and there can be hundreds). `_fetch_risks_for_hostname` returns
  a `(records, truncated)` tuple rather than a bare record, so this fan-out
  hand-rolls the resumable-progress pattern directly against
  `self._fanout_progress["vendor_risks"]` instead of calling
  `Collector._resumable_fanout` — see Performance above for why, and for the
  reference shape.
- **KnowBe4** — `pst_recipients` (per-recipient phishing test results) fans out one
  paginated call per PST id across a bounded thread pool via
  `Collector._resumable_fanout`, the same per-item fan-out pattern as UpGuard's
  `vendor_risks`. PST ids are read from `psts` internally unless a `pst_ids` kwarg
  is given.
- **Salesforce** — auth is username + password + security token (no connected
  app / client id-secret needed); the alternative would be hand-rolling
  Salesforce's SOAP login flow, so `simple_salesforce` is an approved vendor-SDK
  exception alongside `pytenable` (see Guardrails' dependencies rule). Resources
  aren't hand-written per endpoint: `salesforce.json` declares one entry per
  Salesforce object as a flat `{field_name: type}` map, and both the SOQL query
  and the manifest are generated from that file.
- **Tenable.io** — `pytenable`'s export jobs are bespoke server-side machinery
  (polling, chunking) that the base class's generic REST pagination scaffold can't
  express, so this is the other approved vendor-SDK exception.
- **Tenable.sc** — also `pytenable`, for the same reason as Tenable.io
  (`sc.analysis.vulns` is a job-backed export generator). Unlike Tenable.io,
  Tenable.sc is self-hosted with no shared cloud host, so `endpoint` is
  required config. `hosts` and `asset_ips` go through pytenable's raw
  `sc.get(...)` passthrough rather than a dedicated SDK accessor — pyTenable
  has none for these two endpoints — ported from an existing in-house
  extraction script. Both are scoped to a single named Tenable.sc asset list
  (default `"Non Crowdstrike Assets"`, since Crowdstrike-covered hosts are
  already collected via `crowdstrike.py`) via an `asset_name` kwarg, resolved
  to the list's asset id through one `asset` lookup cached per name on the
  instance. `asset_ips` is not `derived_from` `assets`: Tenable.sc returns a
  list's member IPs as a blob of newline-separated IP addresses/ranges
  (`viewableIPs[].ipList`) from a separate per-asset-id endpoint, not a
  nested list of objects on the asset list response — expanding that blob
  into one row per IP happens in `_fetch_page` as a fetch-time transform of
  raw text, the same shape as `qualys.py` converting XML into dicts before
  parse.py ever sees the data.
  **Caveat:** `MANIFEST` column paths in `tenablesc.py` were built from the
  reference extraction script and Tenable.sc's public API reference, not a
  live schema introspection against a real instance — same caveat as
  `wiz.py`, `appomni.py`, `snyk.py`, `cloudflare.py`, `dnsimple.py`,
  `phriendly_phishing.py`, and `vanta.py`. Verify field names/nesting
  against a real instance's response before relying on this collector.
- **Qualys** — raw `requests` against API v2 (mostly; the KnowledgeBase endpoint
  moved to v4 — see `qualys.py`'s module docstring for the EOS history), which
  returns XML rather than JSON. The collector converts each response into plain
  dicts at fetch time, so `parse.py` never has to know XML exists. Pagination
  follows the full next-page URL Qualys returns in a truncated response rather than
  a token. `vulnerability_detections` is derived from the per-host detection list
  (fetched internally as `host_detections`) — one row per (host, QID), mirroring
  the `vulnerabilities` / `vulnerability_remediations` shape in `crowdstrike`.
  `vulnerabilities` here is Qualys' KnowledgeBase (the QID catalogue — severity,
  CVSS, CVE), not a per-host finding.
- **Wiz** — raw `requests` against Wiz's single GraphQL endpoint (`.../graphql`,
  tenant/region-specific — no cross-tenant discovery mechanism exists, unlike
  Crowdstrike's `X-Cs-Region` header, so `api_endpoint` is required config).
  Auth is OAuth2 client-credentials (`grant_type=client_credentials`,
  `audience=wiz-api`) against a token URL that defaults to Wiz's shared Auth0
  endpoint but is overridable via `token_url`, since some tenants are
  provisioned on Cognito with a different URL. All three resources
  (`cloud_security_issues`, `inventory`, `vulnerabilities`) use direct
  cursor-paginated GraphQL queries (`first`/`after`, `pageInfo.hasNextPage`/
  `endCursor`) rather than Wiz's async report-export flow — a deliberate
  choice over the Tenable.io-style export-job pattern, accepting the tradeoff
  that very large tenants may need a future report-based path if direct
  pagination proves too slow or rate-limited in practice.
  **Caveat:** the GraphQL query field paths in `wiz.py`'s `MANIFEST` were built
  from third-party connector documentation, not a live schema introspection —
  Wiz's own docs were unreachable at the time this collector was written.
  Verify field names/nesting against a real tenant's response before relying
  on this collector, and correct `MANIFEST` if they don't match.

- **ServiceNow** — raw `requests` against the Table API
  (`/api/now/table/{table}`), no vendor SDK. Resources aren't hand-written
  per endpoint: `servicenow.json` declares one entry per table as a flat
  `{field_name: type}` map, the same pattern as `salesforce.json` (schema
  drives `sysparm_fields` instead of a SOQL query), including the
  `schema_file`/`SERVICENOW_SCHEMA_FILE` override. Supports two auth modes
  chosen by `auth_type` (config key or `SERVICENOW_AUTH_TYPE`, default
  `"oauth2"`): OAuth2 resource-owner password grant against
  `/oauth_token.do` (`client_id`/`client_secret`/`username`/`password`) or
  HTTP basic auth directly against the REST API user
  (`username`/`password`). Base's flat `required_config_keys` can't express
  "one of these two credential sets", so `servicenow.py` overrides
  `_resolve_config` entirely rather than extending the base class — kept
  local per the anti-overfitting rule since no other collector needs this
  shape yet; `required_config_keys` itself only declares `instance`, so
  `catalog()`'s required-config listing doesn't surface the credential keys
  for either auth mode. Pagination is offset/limit
  (`sysparm_offset`/`sysparm_limit`), the same shape as `sailpoint.py`.
  Query filtering (ServiceNow's encoded-query syntax) is a `sysparm_query`
  kwarg at `collect()` time, never a manifest default.
  **Caveat:** `servicenow.json`'s table/field selection was built from
  ServiceNow's public Table API documentation, not a live schema
  introspection against a real instance — same caveat as `wiz.py` and
  `appomni.py`. Verify field names against a real instance's response
  before relying on this collector.

- **SailPoint** — targets Identity Security Cloud (ISC, the cloud SaaS product
  formerly IdentityNow), not IdentityIQ (self-hosted, a different API entirely).
  Raw `requests` against REST API v3 — generic OAuth2 client-credentials REST,
  no vendor SDK needed. Unlike Wiz, the OAuth token endpoint lives on the same
  host as the API (`<base_url>/oauth/token`), so no separate `token_url`
  config exists. Pagination is offset/limit (`_fetch_page` advances
  `offset + limit` each page), not cursor-based like Okta's Link header or
  Wiz's GraphQL cursor — pagination ends when a page returns fewer than
  `limit` records. `identities`, `accounts`, `access_profiles`, and `roles`
  only carry the fields named in `MANIFEST`; nested entitlement lists on
  `access_profiles`/`roles` are out of scope for this initial cut (no derived
  resource declared for them).

- **AppOmni** — auth is a static bearer token issued out-of-band in the
  AppOmni console (no OAuth flow), the same "just set the header" shape as
  UpGuard's `api_key`. Base URL is tenant-specific
  (`https://<instance>.appomni.com`, `instance` required config, no
  cross-tenant discovery). Pagination is DRF-style: each page's `next` is
  already a complete, pre-parameterised URL, so the cursor threaded through
  `_fetch_page` is that URL rather than an offset/limit pair — once the
  first page is fetched, subsequent requests just `GET` the given `next`
  URL directly. `monitored_services` is the one resource with no
  pagination envelope at all (a bare JSON list). `policies` and
  `posture_policies` hit the same `/policy/` endpoint with different
  default query filters (reference policies vs. monitored-service-config
  policies) — two separate resources, not `derived_from`, since each needs
  its own network call with its own filter.
  **Caveat:** `MANIFEST` column paths in `appomni.py` were built from
  AppOmni's public API reference and a prior in-house extraction script,
  not a live schema introspection against a real tenant — same caveat as
  `wiz.py`. Verify field names/nesting against a real tenant's response
  before relying on this collector.

- **Snyk** — raw `requests` against REST API v3 (JSON:API envelope) plus one
  v1 endpoint that has no REST equivalent (`members`, org members — a bare
  unpaginated list). Static token auth (`Authorization: token <TOKEN>`),
  same "just set the header" shape as AppOmni/UpGuard. `organizations` is
  the only real top-level paginated resource — REST v3's `links.next` is
  already a complete relative path, mirroring `appomni.py`'s DRF `next` URL
  but relative rather than absolute. Snyk has no "all orgs" endpoint for
  members/projects/issues/targets, so each fans out one call (`members`) or
  one paginated loop (`projects`/`issues`/`targets`) per org id across a
  thread pool —
  the same per-item fan-out shape as `knowbe4.py`'s `pst_recipients` (fan
  out, then paginate internally per item), not `derived_from`, since each
  org's members/projects/issues/targets are their own network call rather
  than data nested in the org list response. `_org_id` is injected
  client-side into every member/project/issue/target record. `targets`
  represents the underlying repo (GitHub/GitLab/etc.) a project scans —
  `display_name`, `url`, `is_private`, and the source integration type; it
  has no `tags` field of its own. Repo-level tags live on `projects`
  (`attributes.tags`, a `{key, value}` array); `projects.target_id`
  (`relationships.target.data.id`) is the join key back to `targets.id`.
  **Caveat:** `MANIFEST` column paths in `snyk.py` were built from Snyk's
  public API reference and a prior in-house extraction script, not a live
  schema introspection against a real tenant — same caveat as `wiz.py` and
  `appomni.py`. Verify field names/nesting against a real tenant's response
  before relying on this collector.

- **Cloudflare** — raw `requests` against REST API v4, static API token auth
  (`Authorization: Bearer ...`), same "just set the header" shape as
  AppOmni/Snyk. Base URL is global (`https://api.cloudflare.com/client/v4`)
  — no tenant subdomain or cross-tenant discovery, since the token itself is
  scoped to whatever zones it was issued against. `zones` is the only real
  top-level paginated resource (`page`/`per_page` with a `result_info`
  envelope). Cloudflare has no "all zones' records" endpoint, so
  `dns_records` and `cdn_protected_domains` each fan out one paginated call
  per zone id across a thread pool — the same per-item fan-out shape as
  `snyk.py`'s `projects`/`issues` (`requires: "zones"`, not `derived_from`,
  since each zone's records are their own network call). `dns_records` and
  `cdn_protected_domains` hit the same `/zones/{zone_id}/dns_records`
  endpoint with different default filters — `cdn_protected_domains` passes
  `proxied=true` server-side to return only the records actually routed
  through Cloudflare's CDN — mirroring `appomni.py`'s
  `policies`/`posture_policies` pair.
  **Caveat:** `MANIFEST` column paths in `cloudflare.py` were built from
  Cloudflare's public API reference, not a live schema introspection
  against a real tenant — same caveat as `wiz.py`, `appomni.py`, and
  `snyk.py`. Verify field names/nesting against a real tenant's response
  before relying on this collector.

- **DNSimple** — raw `requests` against REST API v2, static bearer token
  auth (`Authorization: Bearer <token>`), same "just set the header" shape
  as AppOmni/Snyk/Cloudflare. Every v2 endpoint is scoped under an account
  id that isn't known up front, so `_authenticate` calls `whoami` once to
  discover it and caches it on the instance for every subsequent request —
  the same "discover, then route" shape as Crowdstrike's cloud-region
  lookup, just an account id instead of a base URL. Base URL defaults to
  DNSimple's production endpoint but is overridable via `endpoint` config
  (DNSimple also runs a sandbox environment at a different host).
  `domains` is page/per_page with a `pagination` envelope (`total_pages`),
  the same shape as `cloudflare.py`'s `zones`. `zone_records` has no
  "all zones' records" endpoint, so it fans out one paginated
  `GET /{account}/zones/{zone}/records` call per zone across a thread pool
  (`requires="domains"`, zone name = domain name), the same per-item
  fan-out shape as `cloudflare.py`'s `dns_records`; a domain with no hosted
  zone 404s and contributes no rows, and `_zone` is injected client-side.
  The reference implementation this collector was ported from also did
  live DNS resolution (MX/TXT/DMARC/DKIM lookups against a hardcoded public
  resolver) per domain; that was deliberately left out here since it
  requires a new dependency (`dnspython`) outside posture's approved
  dependency list and isn't a DNSimple API response at all — revisit only
  with explicit approval to add the dependency.
  **Caveat:** `MANIFEST` column paths in `dnsimple.py` were built from
  DNSimple's public API reference, not a live schema introspection against
  a real account — same caveat as `wiz.py`, `appomni.py`, `snyk.py`, and
  `cloudflare.py`. Verify field names/nesting against a real account's
  response before relying on this collector.

- **PhriendlyPhishing** — raw `requests` against REST API v0.1, OAuth2
  client-credentials auth, but against a dedicated auth host
  (`auth.api.phriendlyphishing.com`) separate from the API host
  (`api.phriendlyphishing.com`) — the same "auth host differs from API
  host" shape as Wiz, just without Wiz's regional discovery, since
  PhriendlyPhishing has one fixed pair of hosts. Pagination is a plain
  `page`/`page_size` scheme, the same shape as `knowbe4.py`'s list
  resources. `clicks` also takes a server-side `start_time`/`end_time`
  date range; the collector defaults it to the trailing 366 days (plus
  one day forward, mirroring the reference extraction script this
  collector was ported from) but kwargs win over that default per the
  locked kwargs-override-defaults rule.
  **Caveat:** `MANIFEST` column paths in `phriendly_phishing.py` were
  built from the reference extraction script, not a live schema
  introspection against a real tenant — same caveat as `wiz.py`,
  `appomni.py`, `snyk.py`, `cloudflare.py`, and `dnsimple.py`. Verify
  field names/nesting against a real tenant's response before relying on
  this collector.

- **Vanta** — raw `requests` against REST API v1, OAuth2 client-credentials
  auth against a fixed global host (`https://api.vanta.com/oauth/token`,
  scope `vanta-api.all:read vanta-api.all:write`) — the same
  client-credentials shape as `wiz.py`, but with no regional/tenant
  discovery or `token_url` override, since Vanta has one shared API host
  for every tenant. Every resource (`controls`, `documents`, `frameworks`,
  `groups`, `integrations`, `monitored_computers`, `people`, `tests`,
  `vulnerabilities`, `vulnerable_assets`, `vulnerability_remediations`) is
  its own top-level paginated endpoint — no fan-out, no `derived_from`.
  Pagination is cursor-based (`pageSize`/`pageCursor` query params) with a
  `results.data` / `results.pageInfo.hasNextPage` / `results.pageInfo.endCursor`
  envelope, ported from an existing in-house extraction script.
  **Caveat:** `MANIFEST` column paths in `vanta.py` were built from Vanta's
  public API reference and that extraction script, not a live schema
  introspection against a real tenant — same caveat as `wiz.py`,
  `appomni.py`, `snyk.py`, `cloudflare.py`, `dnsimple.py`, and
  `phriendly_phishing.py`. Verify field names/nesting against a real
  tenant's response before relying on this collector.

- **Crowdstrike Identity Protection (IDP)** — Falcon Identity Protection
  (formerly Preempt), a distinct product surface from Falcon endpoint
  protection and Falcon Cloud Security, hence a separate collector
  (`env_prefix = "CROWDSTRIKE_IDENTITY"`) rather than extending
  `crowdstrike.py`. Auth and cloud-region discovery (`X-Cs-Region`) mirror
  `crowdstrike.py`/`crowdstrike_cspm.py` exactly — flagged as a
  `# CANDIDATE` for promotion to `base.py` rather than promoted now, per
  the anti-overfitting rule. `entities` (identity inventory/risk) is the
  one resource with no REST query-then-entities pair — CrowdStrike exposes
  Identity Protection's inventory only through a GraphQL endpoint
  (`/identity-protection/combined/graphql/v1`, cursor-paginated via
  `pageInfo.hasNextPage`/`endCursor`), the same GraphQL shape as `wiz.py`.
  `entity_risk_factors` explodes the nested `riskFactors` list into its own
  grain (`derived_from` `entities`), the same pattern as
  `vulnerability_remediations` off `vulnerabilities`. `detections`
  (identity-related alerts) instead uses the shared Falcon Alerts API v2
  (`/alerts/queries/alerts/v2` + `/alerts/entities/alerts/v2`, filtered to
  `product:'idp'` by default), the same query-ids-then-fetch-entities shape
  as `crowdstrike.py`'s `hosts`, just batching `composite_ids` instead of
  device ids.
  **Caveat:** `MANIFEST` column paths and the GraphQL query in
  `crowdstrike_identity.py` were built from CrowdStrike's public API
  reference and third-party connector documentation, not a live schema
  introspection against a real tenant — same caveat as `wiz.py`,
  `appomni.py`, `snyk.py`, `cloudflare.py`, `dnsimple.py`,
  `phriendly_phishing.py`, and `vanta.py`. Verify field names/nesting
  against a real tenant's response before relying on this collector.

- **Whistic** — raw `requests` against Whistic's Public API
  (`https://public.whistic.com/api`), static token auth via the `api-key`
  header — same "just set the header" shape as AppOmni/Snyk/UpGuard.
  `endpoint` is optional config (not in `required_config_keys`, since it has
  a default), normalized manually in `__init__` the same way `dnsimple.py`
  handles its optional `endpoint` override. `vendors` (the catalog list)
  and `vendor_details` (one `GET /vendors/{identifier}` fan-out per id,
  same per-item fan-out shape as `appomni.py`'s `policy_risk_summary`) are
  the only two resources — Whistic's write endpoints (vendor
  create/update, vendor intake form submission) are out of scope, since
  posture is a read-only collection library.
  **Caveat — pagination inferred, not confirmed:** `GET /vendors` returns
  a bare JSON array with no envelope, `next` link, or total count.
  Whistic's own Python SDK (a separate project this collector was analysed
  against, not vendored) assumes an older `_embedded`/`_links.next.href`
  HATEOAS shape that the current public OpenAPI spec (fetched live from
  `/docs/api-docs` — the SDK itself predates or doesn't match it) no
  longer documents. The current spec's `cursor` query param is described
  only as "begin with the vendor after the specified one," with no field
  named as the cursor source; `_fetch_page` assumes the last returned
  vendor's own `identifier` is a valid cursor value and stops once a page
  comes back shorter than `page_size` — the same short-page heuristic
  `knowbe4.py` used pre-cursor-migration. **Verify this actually
  terminates against a live tenant before relying on this collector** —
  same caveat tier as `wiz.py`/`appomni.py`/etc., but stronger, since the
  pagination mechanism itself (not just field names) is unverified.
  `MANIFEST` column paths for both resources come from the OpenAPI spec's
  `VendorPreview`/`Vendor` schemas, not a live tenant response.

- **Cortex Cloud** (Palo Alto) — raw `requests` against Cortex Cloud's
  Public API (`https://api-<fqdn>/public_api/v1/...`), no vendor SDK.
  Shares its API platform with Cortex XDR/XSIAM, hence the `x-xdr-*`
  header names. Auth is a static API key + a separate numeric API Key ID
  (`token`/`api_key_id` config, `Authorization`/`x-xdr-auth-id` headers —
  "Standard" key mode; Cortex also documents an "Advanced" mode with a
  per-request nonce/timestamp/sha256 hash, not implemented here since
  Standard is what was verified against a live tenant). `endpoint` is
  required config (the tenant's `api-<fqdn>` host), same no-cross-tenant-
  discovery shape as `wiz.py`'s `api_endpoint`.
  **Live-verified against a real tenant** (2026-08-19), including two
  corrections to Cortex's own published docs: `assets`
  (`POST /public_api/v1/assets`) caps at page size 1000, not the
  documented 5000 (confirmed via a 400 at 1001); `issues`
  (`POST /public_api/v1/issue/search`) caps at 100. The two endpoints'
  response envelopes also use inconsistent key casing — `reply.data[]`/
  `reply.metadata.total_count` for `assets` vs. `reply.DATA[]`/
  `reply.TOTAL_COUNT` for `issues` — both handled explicitly in
  `_fetch_page` rather than assumed identical.
  Every record on both endpoints comes back with **literal flat keys
  containing dots** (`{"xdm.asset.name": "..."}` is one key, not a nested
  object) rather than genuinely nested JSON — `_nest_dotted_keys` reshapes
  each record into a real nested dict at fetch time so `parse.py`'s
  dotted-path column lookup works unchanged, the same "transform before
  parse.py ever sees it" shape `qualys.py`/`tenablesc.py` use for XML.
  `assets` is a unified multi-cloud/identity/code/image inventory
  spanning dozens of asset types under one `xdm.asset.*` envelope;
  `MANIFEST` only declares the core fields present on every type (id,
  name, provider, type classification, cloud region/account, observed
  timestamps, related-issues/cases rollups) — the many type-specific
  extension namespaces sampled live (`xdm.identity.*`, `xdm.image.*`,
  `xdm.code.*`, `xdm.software_package.*`, and more) are out of scope for
  this initial cut. `issues` covers both misconfiguration and
  vulnerability-style findings in one feed (Cortex's own terminology) —
  there is no separate CVE-only endpoint in the surface explored here,
  unlike Crowdstrike/Qualys's split `vulnerabilities` resource.

- **Kandji** — Apple-only MDM (macOS/iOS/iPadOS/tvOS), rebranded to "Iru";
  existing tenant hosts still resolve at
  `https://<subdomain>.api.kandji.io` (or `.api.eu.kandji.io` for EU
  tenants), so `api_url` is required config (the full tenant host, no
  cross-tenant discovery mechanism) rather than a bare subdomain — same
  "no discovery, operator supplies the host" shape as `wiz.py`'s
  `api_endpoint`. Auth is a static bearer token issued out-of-band in the
  Kandji console, same "just set the header" shape as
  AppOmni/Snyk/UpGuard. Raw `requests`, no vendor SDK. Two pagination
  shapes coexist: `devices` returns a bare JSON list with no envelope at
  all (limit/offset, stop on a short page — the same shape as AppOmni's
  `monitored_services`); `blueprints` and `vulnerabilities` return a
  DRF-style `{"count", "next", "previous", "results"}` envelope where
  `next` is already a complete URL — the same cursor shape as AppOmni's
  `policies`/`open_policy_issues`, despite `vulnerabilities` using
  `page`/`size` rather than `limit`/`offset` for its own default params
  (irrelevant once `next` takes over). `device_details` fans out one
  `GET /devices/{id}/details` call per id via `Collector._resumable_fanout`
  (ids read from `devices` internally unless a `device_ids` kwarg is
  given) — the same per-item fan-out shape as `appomni.py`'s
  `policy_risk_summary`.
  **Caveat:** `MANIFEST` column paths were built from Kandji's public API
  reference, a third-party Python wrapper (frefrik/python-kandji), and a
  third-party MCP server built against this API, not a live schema
  introspection against a real tenant — same caveat tier as `wiz.py`,
  `appomni.py`, `snyk.py`, `cloudflare.py`, `dnsimple.py`,
  `phriendly_phishing.py`, `vanta.py`, and `crowdstrike_identity.py`.
  `device_details`'s security-posture field nesting (FileVault/firewall/
  Gatekeeper/SIP) is a best-effort guess at naming conventions, not a
  confirmed response shape. `vulnerabilities`' exact grain (a CVE catalog
  vs. a per-device detection feed) is also unconfirmed, though the
  endpoint path itself was independently corroborated by two sources.
  Verify field names/nesting and the vulnerabilities grain against a real
  tenant's response before relying on this collector.

- **SonarCloud** — raw `requests` against SonarCloud's hosted Web API
  (`https://sonarcloud.io/api`), no vendor SDK. This targets SonarCloud
  (SaaS), not self-hosted SonarQube Server — a different API surface,
  unverified here. Auth is a static user token
  (`Authorization: Bearer <token>`), same "just set the header" shape as
  Snyk/AppOmni/UpGuard. `organization` is required config: almost every
  endpoint is scoped to one org key and SonarCloud has no cross-org
  discovery, same no-discovery shape as Wiz's `api_endpoint`.
  `organizations` and `projects` are real top-level resources, `p`/`ps`
  paginated with a `paging.total` envelope, the same shape `issues` uses.
  `hotspots`, `quality_gate_status`, and `measures` are all per-project —
  SonarCloud has no org-wide endpoint for any of the three — so each fans
  out one call per project key across a thread pool via
  `Collector._resumable_fanout`, the same per-item fan-out shape as
  `snyk.py`'s `members`/`projects`/`issues` (not `derived_from`, since each
  project's data is its own network call). `measures` explodes to one row
  per (project, metric) rather than one wide row per project, since grain
  is sacred and SonarCloud's response nests a metric list per component.
  **Live-verified against a real organization** (2026-08-24): all six
  resources (`organizations`, `projects`, `issues`, `hotspots`,
  `quality_gate_status`, `measures`) returned correctly-shaped data,
  including the `hotspots` field set, which was the lower-confidence guess
  at write time. `docs/credentials/sonarcloud.md` documents provisioning a
  dedicated read-only organization member and generating its user token.

- **runZero** — raw `requests` against runZero's Export API
  (`https://console.runzero.com/api/v1.0`), no vendor SDK. Auth is a static
  Export API key issued out-of-band in the runZero console — export-only by
  design, no write capability regardless of the generating user's own role.
  `assets` hits the bulk export endpoint (`/export/org/assets.json`), a
  single unpaginated request returning a bare JSON array — the same
  "no envelope at all" shape as Kandji's `devices`/AppOmni's
  `monitored_services`. `endpoint` is optional config for a self-hosted
  console, same shape as DNSimple's `endpoint`.
  **Caveat:** ported from a legacy in-house extraction script (which called
  only `/export/org/assets.json`) and cross-checked against runZero's public
  Export API documentation — no live credentials were available to verify
  this collector against a real org's response. Same caveat tier as
  `wiz.py`/`appomni.py`/etc., but stronger: verify both field names and the
  single-unpaginated-call assumption before relying on this collector.

- **Select Star** — raw `requests` against Select Star's REST API v1
  (`https://api.production.selectstar.com`), no vendor SDK. Auth is a static
  token, header shape `Authorization: Token <token>` (Select Star's own
  scheme, not `Bearer`). Pagination is DRF-style with `next` already a
  complete URL, the same shape as AppOmni's `policies`/`open_policy_issues`.
  `databases` and `tables` are the only two resources — the pair the legacy
  extraction script this collector was ported from actually called.
  **Caveat:** ported from that legacy script and cross-checked against
  Select Star's public API documentation — no live credentials were
  available to verify this collector against a real workspace's response.
  Same caveat tier as `wiz.py`/`appomni.py`/etc. Verify field names/nesting
  before relying on this collector.

- **Obsidian Security** — raw `requests` against Obsidian's GraphQL API
  (`https://api.obsec.io/v1/gql`), no vendor SDK. Auth is a static bearer
  token, same "just set the header" shape as AppOmni/Snyk/UpGuard, over
  GraphQL POST rather than REST GET. Pagination is cursor-based but with
  Obsidian's own field names (`has_more_results`/`cursor` on the top-level
  query result) rather than `wiz.py`'s Relay-style `pageInfo.hasNextPage`/
  `endCursor`. `posture_rules` (`ListGlobalPostureRules`) is the global
  posture-rule catalogue; `posture_rule_tenant_states` explodes each rule's
  nested `tenant_states` list to its own grain (`derived_from`
  `posture_rules`), the same shape as `crowdstrike.py`'s
  `vulnerability_remediations`. `posture_scores`
  (`getScoreRankWidgetData`) reshapes a `{key: {...metrics}}` dict per
  scoring period into one flat record per key at fetch time — the same
  "transform before parse.py ever sees it" shape `qualys.py`/`tenablesc.py`
  use for their own non-record-list envelopes — and folds both groupings
  the query returns in one call (by platform, by compliance standard) into
  one resource distinguished by a `group_by` column, rather than querying
  twice for data already in hand. Defaults to the trailing day
  (`interval: DAILY`), kwargs win over that default per the locked
  kwargs-override-defaults rule.
  **Caveat:** ported directly from a legacy in-house extraction script, not
  a live schema introspection — no live credentials were available to
  verify this collector. Same caveat tier as `wiz.py`/`appomni.py`/etc., but
  stronger for `posture_scores`' pagination: the reference script advances
  the cursor using only the platforms grouping's `has_more_results`/
  `cursor` and ignores the compliance grouping's own pagination state
  entirely — carried forward unchanged rather than guessed at, which means
  a tenant with more compliance-grouped pages than platform-grouped ones
  could see that grouping truncate silently. Verify field names, the
  compliance-side pagination assumption, and the score payload's actual
  metric keys against a real tenant's response before relying on this
  collector.

- **Nullify** — raw `requests` against Nullify's REST API
  (`https://api.<TENANT>.nullify.ai`), no vendor SDK. Auth is a static
  service-account token, same "just set the header" shape as
  AppOmni/Snyk/UpGuard. `endpoint` is required config (tenant-scoped host,
  no cross-tenant discovery, same shape as Wiz's `api_endpoint`).
  `github_owner_id` is also required config, not a per-call kwarg — it
  identifies which tenant's data a request reads (the "who am I" side of
  the locked kwargs-vs-config split), appended to every request rather than
  exposed for the caller to vary per collect(). Pagination is cursor-based
  (`limit`/`nextToken` on the request, `nextToken` echoed back on the
  response). `repositories` (`/admin/repositories`), `sca_events`
  (`/sca/events`), `sast_events` (`/sast/events`).
  **This collector replaces a legacy in-house extraction script confirmed
  broken against Nullify's current public API** (checked directly against
  docs.nullify.ai, 2026-08-25): the legacy script paginated both event
  endpoints with a `fromEvent` query param and read the next cursor from a
  `nextEventId` response field — neither exists in Nullify's documented API;
  the real pagination contract is `nextToken` on both sides. Against the
  real API the legacy script's loop would have silently stopped after one
  page every time. The legacy script's fourth resource,
  `/sca/counts/severity/latest`, does not appear anywhere in Nullify's
  current public API reference (checked the dependency-analysis, SAST, and
  admin pages directly) and was dropped rather than kept as a resource that
  would 404 against every real tenant.
  **Caveat — weaker tier than usual:** endpoint paths, auth, and the
  pagination contract are confirmed from Nullify's public docs, but the
  docs' response-schema examples are embedded in a rendered component this
  collector could not extract as plain text, so `MANIFEST`'s field names
  are inferred from each endpoint's documented purpose and comparable
  collectors in this codebase (`snyk.py`'s `issues`, `wiz.py`'s
  `vulnerabilityFindings`) rather than confirmed against any schema or
  example payload. No live tenant was available to verify against. Treat
  every column name as a guess and verify against a real tenant's response
  before relying on this collector.

- **UptimeRobot** — raw `requests` against API v2
  (`https://api.uptimerobot.com/v2/<method>`), no vendor SDK. Every method
  is an HTTP `POST` with a form-encoded body; the API key is an `api_key`
  body field, not a header, so `_authenticate` establishes no session
  state and a bad key surfaces as `UnauthorizedSignal` from `_post` on the
  first call (a `stat: fail` body with HTTP 200 — the status code can't be
  trusted). One fixed base URL, no tenant host, no OAuth. A read-only key
  (`ur…` prefix) is preferred over a main key (`u…`, read + write) but both
  work. `monitors`, `monitor_logs`, and `monitor_response_times` all hit
  the single `getMonitors` endpoint with different expansion params —
  `monitors` requests `custom_uptime_ratios=1-7-30-90` +
  `all_time_uptime_ratio` and splits the dash-joined ratio/`custom_down_durations`
  strings into `uptime_ratio_<n>d`/`down_duration_<n>d` columns at fetch
  time (the `qualys.py`/`cortex_cloud.py` "reshape before parse.py" shape);
  `monitor_logs`/`monitor_response_times` explode each monitor's nested
  `logs`/`response_times` array into their own grain in `_fetch_page`
  rather than via a `derived_from` manifest, since each needs its own
  `getMonitors` call with its own params. `monitor_logs` is **time-window
  scoped** because the log feed is noisy/unbounded: bare `collect()`
  returns the trailing 48 h, overridable with a synthetic
  `logs_window_hours` kwarg (popped before the request, never sent) or the
  native `logs_start_date`/`logs_end_date` epoch params — the latter lets a
  caller build a delta extractor. The two window kwargs are mutually
  exclusive (`ValueError`). This is kwarg-driven query scoping, not
  stateful incremental sync — no checkpoint is stored; each run is still a
  full point-in-time pull of whatever window is asked for. `account`
  (`getAccountDetails`, one row) and `alert_contacts` (`getAlertContacts`,
  offset/limit on a top-level `total`) are separate simple endpoints.
  **Live-verified** against a real account (2026-08-29): all five
  resources' envelopes, field names, and the `stat: fail` error shape.

- **Healthchecks.io** — raw `requests` against the Management API v3
  (`https://healthchecks.io/api/v3/`), no vendor SDK. Auth is a static
  per-project key in the `X-Api-Key` header; the collector targets the
  **read-only** key (`hcr_` prefix), which can list checks and read flips
  but not channels or ping detail. `api_url` is optional config
  (default `https://healthchecks.io`, normalised) for self-hosted
  instances — the DNSimple `endpoint` shape. `checks` is one unpaginated
  `GET /checks/` (`{"checks": [...]}`, no envelope pagination), with
  optional server-side `slug`/`tag` filters. `flips` (the recorded up/down
  history, `up` = 1 recovered / 0 down) is a per-check fan-out via
  `Collector._resumable_fanout` (`requires: "checks"`, not `derived_from` —
  each check's flips are their own `GET /checks/<id>/flips/` call), keyed
  by `uuid or unique_key` since the flips endpoint accepts either;
  `_check_key`/`_check_name` injected client-side. `flips` is time-window
  scoped (default trailing 90 days) via exactly one of `flips_window_hours`
  (synthetic → native `seconds`), `seconds`, or `start`/`end` (the
  since-instant / delta-extractor form). The native `seconds` param is
  capped at 365 days server-side, so a computed lookback above that raises
  `ValueError` rather than 400ing mid-fan-out — `start`/`end` (uncapped)
  is the path for longer ranges. Both `uuid` and `unique_key` are declared
  in `MANIFEST` so the collector also works with a read-write key.
  **Live-verified** against a real project with a read-only key
  (2026-08-29): `checks`, `flips` (`unique_key` addressing, the window
  params, and the 365-day `seconds` cap).

- **Miro** — raw `requests` against REST API v2 (`https://api.miro.com`),
  no vendor SDK. Miro has **no client-credentials grant** (the token
  endpoint 401s `Unsupported grant type`), so auth is a static
  `authorization_code`-minted access token supplied as `access_token`
  config (`MIRO_ACCESS_TOKEN`) — the app's `client_id`/`client_secret`
  are unused. The org id every `/v2/orgs/{org_id}/...` endpoint needs is
  discovered via a one-time `GET /v1/oauth-token` in `_authenticate`
  (cached on the instance), the DNSimple/Crowdstrike "discover then route"
  shape. Two pagination shapes: offset/limit with a `total` envelope
  (`boards`, `board_members`) and Miro's `cursor`-list (`org_members`,
  `teams`, `team_members`, `audit_logs`). Three per-item fan-outs via
  `Collector._resumable_fanout`: `board_members` and `board_classifications`
  over boards (`requires: "boards"`; `board_classifications` takes each
  board's `team.id` for its path and treats a 404 as "no label" → absent
  row), `team_members` over teams (`requires: "teams"`). `boards` flattens
  the board object's `policy.sharingPolicy`/`policy.permissionsPolicy`
  into `sharing_*`/`perm_*` columns — the exposure signal. `audit_logs`
  is time-window scoped (the endpoint requires `createdAfter`/
  `createdBefore`): default trailing 30 days, overridable with
  `window_hours` (synthetic) or `created_after`/`created_before`
  (epoch/ISO, mutually exclusive with `window_hours`). A 403
  `insufficientPermissions` raises `PermissionDeniedSignal` (fail fast,
  message kept) since it means a missing scope or non-Enterprise plan, not
  a transient error.
  **Partly live-verified** (2026-08-29): `boards` and `board_members`
  against a non-Enterprise team. `org_members`, `teams`, `team_members`,
  `audit_logs`, `board_classifications` were built from Miro's published
  OpenAPI reference only — the test token lacked the Enterprise scopes —
  same caveat tier as `wiz.py`/`appomni.py`. Verify field names/nesting
  against a real Enterprise tenant before relying on those five.

## Version bumps

The version number is duplicated in two places — `pyproject.toml`'s `version` and
`src/posture/__init__.py`'s `__version__`. Any version bump touches both in the same
change; never update just one.

`tests/test_posture.py::test_version` asserts `posture.__version__` against a hardcoded
string. Any version bump updates that assertion too, in the same change.
