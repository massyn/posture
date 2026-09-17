"""``posturecollect`` — extract every table from every registered posture
collector and write it to parquet.

    posturecollect
    posturecollect --include crowdstrike endoflife
    posturecollect --output ./data --history
    posturecollect --include qualys --debug
    posturecollect --thread 5

By default, every registered source with all of its required environment
variables set is collected (``catalog(filter="environment")`` — a no-auth
source, e.g. ``endoflife``/``macadmins``, is never picked up here since it
has nothing to check). ``--include`` overrides that entirely: only the named
source(s) are collected, unconditionally — this is the one way to reach a
no-auth source, or to run a single source regardless of what's configured.

Every resource of every selected source is streamed page-by-page
(``Collector.collect_page()``) straight into a parquet file via
``pyarrow.parquet.ParquetWriter``, one row group per page — peak memory is
bounded to a single page, never the whole resource. Each file is written to
a ``.tmp`` sibling and renamed into place only once every page has been
written successfully, so a failure partway through a resource never leaves
a truncated file behind; the previous run's file (if any) is left untouched
in that case.

Output layout under ``--output`` (default ``./output``), one file per
``<source>_<resource>``:

- default: ``<output>/<source>_<resource>.parquet`` (overwritten every run)
- ``--history``: ``<output>/<source>_<resource>/<YYYY.MM.DD>.parquet`` (one
  dated snapshot per day, overwritten if run again the same day)

A failure on one source or resource is logged and does not stop the rest of
the run — ``main()`` returns a non-zero exit code if anything failed, so a
scheduler can still detect a partial run without losing the sources that
did succeed.

Sources are collected concurrently, ``--thread`` (default 3) at a time —
each source gets its own ``CCM`` instance and writes only to its own
``<source>_<resource>.parquet`` file(s), so sources share no mutable state
and can safely run in parallel. Resources within one source are still
collected serially.
"""

from __future__ import annotations

import argparse
import logging
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

from posture import CCM, catalog
from posture.exceptions import PostureError

logger = logging.getLogger("posture.cli")

_ARG_FLAGS = {
    "include": "--include",
    "output": "--output",
    "history": "--history",
    "debug": "--debug",
    "thread": "--thread",
}


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="posturecollect", description=__doc__.split("\n\n", 1)[0]
    )
    parser.add_argument(
        "--include",
        nargs="+",
        metavar="SOURCE",
        default=None,
        help=(
            "only collect these source(s), regardless of environment "
            "variables — the one way to reach a no-auth source"
        ),
    )
    parser.add_argument(
        "--output",
        default="output",
        metavar="PATH",
        help="directory to write parquet files into (default: %(default)s)",
    )
    parser.add_argument(
        "--history",
        action="store_true",
        help=(
            "write one dated file per table per day "
            "(<output>/<table>/<YYYY.MM.DD>.parquet) instead of "
            "overwriting a single <output>/<table>.parquet"
        ),
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="verbose debug-level logging, including from posture's own collectors",
    )
    parser.add_argument(
        "--thread",
        type=int,
        default=3,
        metavar="N",
        help="number of sources to collect concurrently (default: %(default)s)",
    )
    return parser.parse_args(argv)


def _log_parameters(args: argparse.Namespace, argv: list[str] | None) -> None:
    """Log every resolved parameter, tagging each as explicitly passed or
    defaulted — helpful when debugging a run without re-reading the
    command line that kicked it off."""
    raw_argv = sys.argv[1:] if argv is None else argv
    for name, value in vars(args).items():
        flag = _ARG_FLAGS.get(name)
        origin = "explicit" if flag and flag in raw_argv else "default"
        logger.info("parameter %s = %r (%s)", name, value, origin)


def _select_sources(include: list[str] | None) -> dict[str, Any]:
    """Resolve which sources to collect, per the module docstring's rules."""
    if include is None:
        return catalog(filter="environment")

    all_sources = catalog()
    unknown = [name for name in include if name not in all_sources]
    if unknown:
        raise SystemExit(
            f"Unknown source(s): {', '.join(unknown)}. "
            f"Available: {', '.join(sorted(all_sources))}"
        )
    return {name: all_sources[name] for name in include}


def _output_path(output_dir: Path, table: str, *, history: bool) -> Path:
    if history:
        today = datetime.now(timezone.utc).date()
        return output_dir / table / f"{today:%Y.%m.%d}.parquet"
    return output_dir / f"{table}.parquet"


def _collect_resource(ccm: Any, resource: str, path: Path) -> int:
    """Stream ``resource`` page-by-page into a parquet file at ``path``.

    Writes to a ``.tmp`` sibling and only renames it into place once every
    page has been written without error — a mid-collection failure never
    leaves a truncated file at ``path``.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    writer: pq.ParquetWriter | None = None
    record_count = 0
    try:
        for page in ccm.collect_page(resource):
            table = pa.Table.from_pandas(page, preserve_index=False)
            if writer is None:
                writer = pq.ParquetWriter(tmp_path, table.schema)
            writer.write_table(table)
            record_count += len(page)
    finally:
        if writer is not None:
            writer.close()
    if writer is not None:
        tmp_path.replace(path)
    return record_count


def _collect_source(
    source: str, info: dict[str, Any], output_dir: Path, *, history: bool
) -> list[dict[str, Any]]:
    """Collect every resource of one source, returning one result dict per
    table (``table``, ``records``, ``status`` — "ok" or "failed: <reason>").

    Called from its own thread when ``--thread`` > 1 — each source gets its
    own ``CCM`` instance and writes only to its own ``<source>_<resource>``
    file(s), so sources share no mutable state and can run concurrently.
    """
    try:
        ccm = CCM(source)
    except (PostureError, ValueError) as exc:
        logger.exception("%s: skipped", source)
        return [{"table": source, "records": 0, "status": f"failed: {exc}"}]

    results: list[dict[str, Any]] = []
    for resource in info["resources"]:
        stem = f"{source}_{resource}"
        path = _output_path(output_dir, stem, history=history)
        logger.info("%s.%s: collecting", source, resource)
        try:
            record_count = _collect_resource(ccm, resource, path)
        except PostureError as exc:
            logger.exception("%s.%s: failed", source, resource)
            results.append({"table": stem, "records": 0, "status": f"failed: {exc}"})
            continue
        logger.info(
            "%s.%s: %d record(s) written to %s", source, resource, record_count, path
        )
        results.append({"table": stem, "records": record_count, "status": "ok"})
    return results


def _log_summary(results: list[dict[str, Any]]) -> None:
    """Log a summary table of every table collected this run, in the same
    order sources were submitted, so a run's end state is visible without
    scrolling back through the per-page log lines above it."""
    if not results:
        return
    table_width = max(len(r["table"]) for r in results)
    status_width = max(len(r["status"]) for r in results)
    header = f"{'Table':<{table_width}}  {'Records':>10}  {'Status':<{status_width}}"
    logger.info("Summary:")
    logger.info(header)
    logger.info("-" * len(header))
    for r in results:
        logger.info(
            f"{r['table']:<{table_width}}  {r['records']:>10}  {r['status']:<{status_width}}"
        )


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        force=True,
    )
    _log_parameters(args, argv)

    output_dir = Path(args.output)
    sources = _select_sources(args.include)

    if not sources:
        logger.warning(
            "No sources to collect — set the required environment "
            "variable(s) for a source, or pass --include"
        )
        return 0

    logger.info(
        "Collecting %d source(s) with --thread %d: %s",
        len(sources),
        args.thread,
        ", ".join(sorted(sources)),
    )

    all_results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=args.thread) as pool:
        futures = {
            pool.submit(
                _collect_source, source, info, output_dir, history=args.history
            ): source
            for source, info in sources.items()
        }
        for future, source in futures.items():
            try:
                all_results.extend(future.result())
            except Exception as exc:
                logger.exception("%s: unhandled error", source)
                all_results.append(
                    {"table": source, "records": 0, "status": f"failed: {exc}"}
                )

    _log_summary(all_results)
    had_failure = any(r["status"] != "ok" for r in all_results)
    return 1 if had_failure else 0


if __name__ == "__main__":
    raise SystemExit(main())
