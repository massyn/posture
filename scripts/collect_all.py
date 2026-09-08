"""Extract every runnable/free collector's every table to four destinations
at once: local Parquet (both a "latest" overwritten copy and a dated
"history" snapshot), DuckDB, and Postgres.

    python scripts/collect_all.py
    python scripts/collect_all.py --output /data/posture
    python scripts/collect_all.py --debug

This is the 1.0.0 storage-layer real-workload check called for in
CLAUDE.md's "Path to 1.0.0" section: run postgres/duckdb against real
collection data, appending, before locking write()/write_page()/mode.

Only ``posture.catalog(filter="runnable")`` sources run — every source
whose required env vars are all set, plus every no-auth/free source
(``endoflife``, ``cve_db``). Each page from ``Collector.collect_page()`` is
streamed once to all four destinations rather than materialising a whole
resource in memory:

- Parquet "latest": ``<output>/<tenancy>/<name>.parquet``, overwritten every
  run (``mode="truncate"``).
- Parquet "history": ``<output>/<tenancy>/<name>/<YYYY>/<MM>/<DD>/*.parquet``,
  one dated snapshot per day (``mode="append"``).
- DuckDB and Postgres: both ``mode="append"`` — every run's rows are added
  on top of what's already in the table, never truncated. Postgres
  connection defaults match ``_start_pg.sh`` (the local dev container this
  was verified against); override via ``POSTURE_POSTGRES_*`` env vars or the
  ``--postgres-dsn`` flag for any other target.
"""

from __future__ import annotations

import argparse
import logging
import os

from dotenv import load_dotenv

from posture import CCM, catalog
from posture.exceptions import PostureError
from posture.storage import DuckdbStorage, ParquetStorage, PostgresStorage

load_dotenv()

parser = argparse.ArgumentParser(
    description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
)
parser.add_argument(
    "--output",
    default=os.environ.get("POSTURE_OUTPUT", "output"),
    help="where to write Parquet and the DuckDB file (default: $POSTURE_OUTPUT or ./output)",
)
parser.add_argument(
    "--postgres-dsn",
    default=os.environ.get("POSTURE_POSTGRES_DSN"),
    help="Postgres DSN (default: $POSTURE_POSTGRES_DSN, else the discrete "
    "POSTURE_POSTGRES_HOST/_PORT/_DBNAME/_USER/_PASSWORD env vars, else "
    "the _start_pg.sh dev-container defaults)",
)
parser.add_argument(
    "--debug",
    action="store_true",
    help="log at DEBUG: library internals, per-table reports, skipped sources",
)
args = parser.parse_args()

logging.basicConfig(
    level=logging.DEBUG if args.debug else logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("collect_all")

# _start_pg.sh's dev-container credentials — only used as a fallback when
# neither --postgres-dsn nor POSTURE_POSTGRES_* env vars are set.
_DEV_PG_DEFAULTS = {
    "host": "localhost",
    "port": "5432",
    "dbname": "appdb",
    "user": "postgres",
    "password": "changeme",
}


def _postgres_config() -> dict[str, str]:
    if args.postgres_dsn:
        return {"dsn": args.postgres_dsn}
    if any(f"POSTURE_POSTGRES_{key.upper()}" in os.environ for key in _DEV_PG_DEFAULTS):
        return {}  # let PostgresStorage resolve each discrete key from env
    return dict(_DEV_PG_DEFAULTS)


parquet_latest = ParquetStorage({"path": args.output})
parquet_history = ParquetStorage({"path": args.output})
duckdb_store = DuckdbStorage({"path": os.path.join(args.output, "posture.duckdb")})
postgres_store = PostgresStorage(_postgres_config())

sources = catalog(filter="runnable")
log.info("running %d runnable/free collector(s) -> %s", len(sources), args.output)
skipped = sorted(set(catalog()) - set(sources))
if skipped:
    log.debug("skipping (missing env vars): %s", ", ".join(skipped))

for source in sources:
    ccm = CCM(source)
    for table in ccm.tables():
        name = f"{source}_{table}"
        schema = ccm.column_types(table)
        try:
            rows = 0
            for page in ccm.collect_page(table):
                parquet_latest.write_page(page, name, mode="truncate", schema=schema)
                parquet_history.write_page(page, name, mode="append", schema=schema)
                duckdb_store.write_page(page, name, mode="append", schema=schema)
                postgres_store.write_page(page, name, mode="append", schema=schema)
                rows += len(page)
        except PostureError:
            log.exception("%s: FAILED", name)
            continue
        log.info("%s: %d rows", name, rows)
        log.debug("%s report: %s", name, ccm.report(table))
