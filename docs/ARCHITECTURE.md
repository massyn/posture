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
df = ccm.collect("vulnerability_remediations")     # derived resource — no second API call
ccm.flush_cache()                                  # the only cache invalidation
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
3. **`collect()` returns a complete pandas df, always.** Pagination is internal and
   invisible. All-or-nothing: if the pull dies mid-pagination after retries, raise
   `IncompleteCollection` and return nothing. Partial data does not exist in this
   library's vocabulary — a partial snapshot presented as complete is a compliance lie.
4. **Memory ceiling is one node's RAM, deliberately.** Documented in README as a design
   choice. Collectors are generators internally so a `stream()` API could be added later —
   but do NOT build stream() now.
5. **kwargs = vendor query dialect** (FQL for Crowdstrike). Always optional — bare
   `collect(resource)` must work. Unknown kwargs raise. Never invent a unified
   cross-vendor filter language. Default filters live in the resource definition.
   Where a collector merges kwargs onto its own default params for the same endpoint,
   kwargs must win — an operator overriding a built-in default is expected, not an edge case.
6. **Credentials never travel through kwargs.** Constructor = "who am I";
   kwargs = "what data do I want".
7. **Snapshot semantics.** Full pull, point in time. No incremental sync, ever.
8. **Token refresh mid-run is a base-class concern.** Crowdstrike OAuth tokens live
   ~30 min; pulls can run hours. Re-auth on 401 / proactive refresh inside the pagination
   loop, at the request level. Retry at request level only — never restart a stream
   that has already yielded.
9. **Transient connection errors are retried, not fatal.** `ConnectionError`,
   `Timeout`, and `ChunkedEncodingError` get up to 2 retries with a fixed 5s wait,
   at the request level, in the base class — a network blip must not kill an
   otherwise-healthy collection. Retries exhausted → the underlying exception
   propagates and is wrapped as `IncompleteCollection` same as any other failure.
   This budget is fixed and shared by every collector — if a specific endpoint's
   response is simply slow (a large unpaginated payload, for example), the fix is a
   longer per-request timeout for that endpoint, not a bigger retry budget.
10. **Session cache:** raw records cached post-collect pre-parse, keyed by
    (resource, frozen kwargs). Retained for instance lifetime IFF the resource has derived
    resources declared; otherwise dropped when parse returns. NO TTL. No cache config.
    `flush_cache()` is the only invalidation. Memory-only — never a disk cache.
11. **Raw `requests` for Crowdstrike — no FalconPy.** Rule: vendor SDKs only when the API
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

- ONE parse function handles all datetime parsing. Output is always tz-aware UTC
  (`datetime64[ns, UTC]`) — never naive. Localisation is the consumer's problem.
- Cascade: epoch by magnitude (10 digits = s, 13 = ms, 16 = µs) → ISO 8601 family →
  explicit `format` hint from the manifest for stragglers. Naked timestamps assumed UTC.
- Unparseable → `NaT` + a warning carrying resource, column, sample value, count.
  Never raise mid-collection over a bad value; never pass strings through into a
  datetime column. Same coercion policy for bool and numerics.

## Performance: per-item fan-out

Some resources require one network call per item rather than one paginated call per
resource — Intune's `managed_device_detail`, `device_configuration_detail`, and
`attack_simulation_users`, and MDE's `machine_vulnerabilities`, are the reference
cases (a detail lookup per device id, a per-simulation user-report drain, a
per-machine vulnerability pull). Run at a real tenant's scale, a serial `for` loop
over these is the dominant cost of the whole collection.

- Fan out with a bounded `concurrent.futures.ThreadPoolExecutor` inside the
  collector's `_fetch_page`-family method (`executor.map(_fetch_one, ids)`, or
  `executor.submit` + `as_completed` if you need the machine/simulation id back
  alongside each result — see `mde.py`'s `_fetch_machine_vulnerabilities_page`),
  not an unbounded thread-per-item burst. Worker count is a module constant per
  collector, not a base-class default, since the right ceiling depends on the
  vendor's own throttling — 10 in `intune.py` (`_MAX_FANOUT_WORKERS`), 25 in
  `mde.py` (`_DEFAULT_MACHINE_VULN_MAX_WORKERS`, overridable via a `max_workers`
  kwarg since it mirrors the reference implementation's tuning knob).
- `Collector.__init__` mounts an `HTTPAdapter(pool_maxsize=_HTTP_POOL_MAXSIZE)` on
  the shared session (`base.py`) so concurrent requests from one collector don't
  starve urllib3's connection pool. `_HTTP_POOL_MAXSIZE` must stay >= the largest
  fan-out worker count across all collectors — bump it whenever a collector's
  fan-out width outgrows it.
- `requests.Session` is safe to share across threads for making calls — no lock
  needed around `self._session.get(...)`. Do NOT add locking there.
- Retry/re-auth stays outside the fan-out: `_request_with_retry` in `base.py` wraps
  the *whole* `_fetch_page` call, so a 401/429 raised by any worker propagates up and
  the entire per-item batch is retried as one unit — same all-or-nothing contract as
  paginated resources, just re-fetching already-succeeded items on that path. This is
  deliberate: keeping retry/backoff single-threaded in the base class avoids
  reimplementing rate-limit and auth-refresh logic per collector under concurrency.
  Do not add per-worker retry — if a vendor needs finer-grained retry than "redo the
  batch," that's a new base-class primitive to design deliberately, not something to
  bolt onto one collector.
- This pattern lives in the collector, not `base.py`, per the anti-overfitting rule —
  promote the fan-out helper to `base.py` only once a second collector demonstrably
  needs the identical shape.

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
- **Out of scope for v1 — do not build:** Store/storage backends, `stream()`, TTLs or
  cache configuration, incremental sync, alert delivery, per-collector pip packages,
  unified filter languages.
- Production-ready code only. No placeholder code, no speculative syntax, no TODO-stubs
  that would break at runtime.
- Python 3.10+. Type hints throughout. pytest. Keep it simple — this library is five
  files on purpose; every rejected feature is a file that doesn't exist.

## Collector implementation notes

Per-source rationale and mechanics that don't belong in the user-facing README —
why something is built the way it is, not how to configure or call it.

- **Crowdstrike** — cloud-region auto-discovery is covered under Guardrails above.
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
  (1–60s per vendor, and there can be hundreds), the only posture resource that does
  concurrent per-parent network calls rather than sequential pagination. See
  Performance above for the general fan-out pattern this follows.
- **KnowBe4** — `pst_recipients` (per-recipient phishing test results) fans out one
  paginated call per PST id across a bounded thread pool, the same per-item fan-out
  pattern as UpGuard's `vendor_risks`. PST ids are read from `psts` internally unless
  a `pst_ids` kwarg is given.
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

## Version bumps

The version number is duplicated in two places — `pyproject.toml`'s `version` and
`src/posture/__init__.py`'s `__version__`. Any version bump touches both in the same
change; never update just one.

`tests/test_posture.py::test_version` asserts `posture.__version__` against a hardcoded
string. Any version bump updates that assertion too, in the same change.
