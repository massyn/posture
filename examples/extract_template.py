"""Copy-and-edit extraction script for posture — pick the bits you want, delete the rest.

This is not meant to be run from inside the posture repo unchanged. Copy it into
your own project, then make three decisions:

  1. SCOPE   — everything, one collector, or one table?  (functions below)
  2. SINK    — Parquet, CSV, Postgres, ...?              (pick one `store_*` body)
  3. RUNTIME — plain CLI, an Airflow DAG, a Databricks job? (the block at the bottom)

Every SCOPE function funnels each table through `store()`, which is just an alias
for whichever `store_*` function you kept. `store()` is handed the page *iterator*
straight from `CCM.collect_page()` — the whole table never sits in memory at once.

Environment
-----------
* Each collector reads its own credentials from env vars — run
  ``python -c "import posture, json; print(json.dumps(posture.catalog(), indent=2))"``
  (or see ``docs/``) for the exact names per source. A ``.env`` file is picked up
  automatically.
* ``TENANCY`` (default ``default``) namespaces the output path/table, so several
  tenants can write to the same target without collisions.
* ``POSTURE_OUTPUT`` sets the file-backend output directory (overridden by
  ``OUTPUT`` below).
* Table-backed sinks read ``POSTURE_<BACKEND>_*`` — see
  ``python -c "import posture, json; print(json.dumps(posture.storage_catalog(), indent=2))"``.
"""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import Iterator

import pandas as pd
from dotenv import load_dotenv

from posture import CCM, runnable_sources
from posture.exceptions import PostureError
from posture.storage import ParquetStorage, Storage

load_dotenv()

log = logging.getLogger("extract")

# Overwrite the target every run, or keep a dated snapshot per run.
HISTORY = False
MODE = "append" if HISTORY else "truncate"

# Output directory for the file-backed sinks (Parquet/CSV/JSON/SQLite/DuckDB).
OUTPUT = os.environ.get("POSTURE_OUTPUT", "output")


# ---------------------------------------------------------------------------
# 2. SINK — keep ONE of these, delete the others, then point `store` at it.
#    All bundled backends: parquet, csv, json, sqlite, duckdb, postgres,
#    s3, gcs, bigquery, snowflake. Every one except the Parquet stream uses
#    the identical `Storage(<name>, <config>).write_page(page, name, mode=...)`
#    shape shown in `store_csv` / `store_postgres` — swap the two strings.
# ---------------------------------------------------------------------------
def store_parquet(name: str, pages: Iterator[pd.DataFrame]) -> int:
    """Stream to one Parquet file, appending each page as a row group."""
    rows = 0
    with ParquetStorage({"path": OUTPUT}).write_stream(name, mode=MODE) as stream:
        for page in pages:
            stream.write(page)
            rows += len(page)
    return rows


def store_csv(name: str, pages: Iterator[pd.DataFrame]) -> int:
    """Write each page as a CSV file under a per-table directory."""
    backend = Storage("csv", {"path": OUTPUT})
    rows = 0
    for page in pages:
        backend.write_page(page, name, mode=MODE)
        rows += len(page)
    return rows


def store_postgres(name: str, pages: Iterator[pd.DataFrame]) -> int:
    """Append each page to a Postgres table (one table per `name`)."""
    backend = Storage("postgres", {"dsn": os.environ["POSTURE_POSTGRES_DSN"]})
    rows = 0
    for page in pages:
        backend.write_page(page, name, mode=MODE)
        rows += len(page)
    return rows


# Point this at the sink you kept (or fan out to several inside your own wrapper).
store = store_parquet


# ---------------------------------------------------------------------------
# 1. SCOPE — call one of these from the RUNTIME block at the bottom.
# ---------------------------------------------------------------------------
def extract_table(source: str, table: str) -> None:
    """One table from one collector, e.g. extract_table("qualys", "host_detections")."""
    _run(CCM(source), source, table)


def extract_collector(source: str) -> None:
    """Every table a collector exposes, e.g. extract_collector("crowdstrike")."""
    ccm = CCM(source)
    for table in ccm.tables():
        _run(ccm, source, table)


def extract_all() -> None:
    """Every table of every collector whose credentials are set right now."""
    for source in runnable_sources():
        extract_collector(source)


def _run(ccm: CCM, source: str, table: str) -> None:
    name = f"{source}_{table}"
    try:
        rows = store(name, ccm.collect_page(table))
    except PostureError as exc:
        # A collection that dies mid-stream is deliberately NOT written:
        # a partial snapshot presented as complete is a compliance lie.
        log.error("%s: FAILED — %s", name, exc)
        return
    log.info("%s: %d rows", name, rows)


# ---------------------------------------------------------------------------
# 3. RUNTIME — keep the CLI block; swap in one of the commented blocks below it.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # Usage:  python extract_template.py            -> everything
    #         python extract_template.py crowdstrike        -> one collector
    #         python extract_template.py qualys.host_detections  -> one table
    arg = sys.argv[1] if len(sys.argv) > 1 else "all"
    if arg == "all":
        extract_all()
    else:
        src, _, tbl = arg.partition(".")
        if tbl:
            extract_table(src, tbl)
        else:
            extract_collector(src)


# --- Airflow -------------------------------------------------------------------
# Delete the `if __name__ == "__main__"` block above and drop this file in your
# dags/ folder. One task per collector, so a single source failing doesn't stop
# the rest; retries/alerting hang off the task.
#
# import pendulum
# from airflow.decorators import dag, task
#
#
# @dag(schedule="@daily", start_date=pendulum.datetime(2024, 1, 1), catchup=False)
# def posture_extract():
#     @task
#     def collect(source: str) -> None:
#         extract_collector(source)
#
#     collect.expand(source=list(runnable_sources()))
#
#
# posture_extract()


# --- Databricks --------------------------------------------------------------
# In a notebook job task, after `%pip install posture[parquet]` and setting the
# credential env vars from your secret scope, just call the scope function:
#
# extract_all()
# # or: extract_collector("crowdstrike")
