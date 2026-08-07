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
