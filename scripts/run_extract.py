"""Extract every configured collector's every table to streaming Parquet.

    python scripts/run_extract.py
    python scripts/run_extract.py --debug
    python scripts/run_extract.py --output /data/posture
    python scripts/run_extract.py --history

Only collectors whose required env vars are all set are run (see
``posture.runnable_sources``). Each table is streamed straight to Parquet
one page at a time via ``ParquetStorage.write_stream`` — the whole resource
never sits in memory at once.

Output location, first match wins: ``--output``, then the ``POSTURE_OUTPUT``
env var, then ``./output``. Without ``--history`` each table is written to
``<output>/<tenancy>/<table>.parquet`` and overwritten every run; with
``--history`` it goes to
``<output>/<tenancy>/<table>/<YYYY>/<MM>/<DD>/<table>.parquet`` — one
snapshot per day. (``<tenancy>`` comes from the ``TENANCY`` env var,
default ``default``.)
"""

from __future__ import annotations

import argparse
import logging
import os

from dotenv import load_dotenv

from posture import CCM, catalog, runnable_sources
from posture.exceptions import PostureError
from posture.storage import ParquetStorage

load_dotenv()

parser = argparse.ArgumentParser(
    description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
)
parser.add_argument(
    "--output",
    default=os.environ.get("POSTURE_OUTPUT", "output"),
    help="where to write Parquet (default: $POSTURE_OUTPUT or ./output)",
)
parser.add_argument(
    "--history",
    action="store_true",
    help="keep a dated YYYY/MM/DD snapshot per day instead of overwriting",
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
log = logging.getLogger("run_extract")

mode = "append" if args.history else "truncate"
store = ParquetStorage({"path": args.output})
sources = runnable_sources()

log.info("running %d collector(s) -> %s (mode=%s)", len(sources), args.output, mode)
skipped = sorted(set(catalog()) - set(sources))
if skipped:
    log.debug("skipping (missing env vars): %s", ", ".join(skipped))

for source in sources:
    ccm = CCM(source)
    for table in ccm.tables():
        name = f"{source}_{table}"
        try:
            rows = 0
            with store.write_stream(name, mode=mode) as stream:
                for page in ccm.collect_page(table):
                    stream.write(page)
                    rows += len(page)
        except PostureError as exc:
            log.error("%s: FAILED - %s", name, exc)
            continue
        log.info("%s: %d rows", name, rows)
        log.debug("%s report: %s", name, ccm.report(table))
