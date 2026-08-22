# posture

Runtime-agnostic Python library for CCM (Continuous Control Monitoring) data collection.
The entire contract: credentials in, DataFrame out. Runs unchanged in Docker, Airflow,
Databricks — the library never knows or cares where it executes.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the design behind this
library — the collect/parse split, locked design decisions, manifest schema, and
per-collector implementation notes.

See [`docs/index.md`](docs/index.md) for every supported collector: its required
environment variables, an example query, and the full column schema for each of
its tables.

## Installation

```bash
pip install posture
```

`posture` loads a `.env` file from the current directory (or a parent) automatically
on import — no code changes needed. Variables already set in the environment always
take precedence over `.env` values. Each collector's required variables are listed
on its page in [`docs/index.md`](docs/index.md), e.g.:

```
# .env
CROWDSTRIKE_CLIENT_ID=xxx
CROWDSTRIKE_CLIENT_SECRET=xxx
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

### Paginated retrieval, for large resources

For a resource too large to comfortably hold in memory as one DataFrame (e.g. MDE's
`machine_vulnerabilities`), use `collect_page()` instead — it yields one DataFrame per
underlying API page, so peak memory is bounded to a single page rather than the whole
resource:

```python
from posture import Storage

store = Storage("sqlite", {"path": "posture.db"})
for df in ccm.collect_page("machine_vulnerabilities"):
    store.write_page(df, "machine_vulnerabilities", mode="append")
```

`Storage("sqlite", ...)` mirrors `CCM("crowdstrike", ...)` — one instance, reused across
writes. A concrete class (`from posture.storage import SqliteStorage`) works identically
when the backend is hardcoded rather than a runtime value.

`collect()` is a thin wrapper over `collect_page()` — it just concatenates every page
into one DataFrame — so both share the same all-or-nothing guarantee: if collection
fails partway through, an exception propagates and no partial data is left for the
caller to mistake for a complete snapshot.

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
(e.g. `region`, `base_url`) aren't tracked as data, so check a source's page in
[`docs/index.md`](docs/index.md) for those.

`storage_catalog()` is the same idea for the storage layer:

```python
from posture import storage_catalog

storage_catalog()
# {
#   "csv":      {"class_name": "CsvStorage", "required_config": {"path": "POSTURE_CSV_PATH"}, "optional_config": {}},
#   "postgres": {"class_name": "PostgresStorage", "required_config": {}, "optional_config": {"dsn": "POSTURE_POSTGRES_DSN", "host": "POSTURE_POSTGRES_HOST", ...}},
#   ...
# }
```

Same guarantees — no instantiation, no writes, no credentials needed. Postgres's config
keys all show up as *optional* here even though one specific combination (`dsn` alone,
or all of `host`/`dbname`/`user`/`password`) is actually required — that either/or logic
lives in `PostgresStorage.__init__`, not in a flat required/optional key list.

## Example: export Crowdstrike hosts to local JSON

```python
from posture import CCM, write_storage

# CROWDSTRIKE_CLIENT_ID / CROWDSTRIKE_CLIENT_SECRET must be set in the environment
ccm = CCM("crowdstrike")
df = ccm.collect("hosts")

write_storage(df, "json", "hosts", config={"path": "output"}, mode="truncate")

print(f"Wrote {len(df)} hosts to output/hosts.json")
```

### Storage: writing a DataFrame somewhere durable

```python
from posture import write_storage

write_storage(df, "csv", "hosts", config={"path": "output"})                 # output/hosts.csv
write_storage(df, "parquet", "hosts", config={"path": "output"})             # output/hosts.parquet
write_storage(df, "sqlite", "hosts", config={"path": "output/posture.db"})   # table "hosts"
write_storage(df, "duckdb", "hosts", config={"path": "output/posture.duckdb"})  # table "hosts"
write_storage(df, "postgres", "hosts", config={"dsn": "postgresql://..."})   # table "hosts"
write_storage(                                                               # same, discrete keys
    df, "postgres", "hosts",
    config={"host": "...", "dbname": "...", "user": "...", "password": "..."},
)
```

`storage` is one of `"csv"`, `"json"`, `"parquet"`, `"sqlite"`, `"duckdb"`, `"postgres"`.
Postgres accepts either a single `dsn` or discrete `host`/`port`/`dbname`/`user`/
`password` keys (same convention every collector uses for its own credentials,
resolved from `POSTURE_POSTGRES_HOST` etc. if not passed explicitly) — `dsn` takes
precedence if both are given.

`mode` controls both overwrite behaviour and history:

- `"truncate"` (the default — latest load is all posture cares about by default) —
  overwrites/replaces in place: `output/hosts.csv`, or table `hosts` recreated.
- `"append"` — keeps a dated snapshot per day: `output/2026/08/22/hosts.csv`, or rows
  appended to the existing `hosts` table. Opt in deliberately — it has real storage
  growth implications the default doesn't.

Every file write goes through a temp file and an atomic rename, so a failure partway
through never leaves a broken file at the real path. For a paginated collection, use
`write_page()` on a backend instance instead of `write_storage()` — see
[Paginated retrieval](#paginated-retrieval-for-large-resources) above.

## Supported sources

See [`docs/index.md`](docs/index.md) for the full list of collectors, each with
its required environment variables, an example query, and the column schema for
every table it exposes.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src tests
black src tests
```
