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
  members/projects/issues, so each fans out one call (`members`) or one
  paginated loop (`projects`/`issues`) per org id across a thread pool —
  the same per-item fan-out shape as `knowbe4.py`'s `pst_recipients` (fan
  out, then paginate internally per item), not `derived_from`, since each
  org's members/projects/issues are their own network call rather than
  data nested in the org list response. `_org_id` is injected client-side
  into every member/project/issue record.
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
  `domains` is the only resource — page/per_page with a `pagination`
  envelope (`total_pages`), the same shape as `cloudflare.py`'s `zones`.
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

## Version bumps

The version number is duplicated in two places — `pyproject.toml`'s `version` and
`src/posture/__init__.py`'s `__version__`. Any version bump touches both in the same
change; never update just one.

`tests/test_posture.py::test_version` asserts `posture.__version__` against a hardcoded
string. Any version bump updates that assertion too, in the same change.
