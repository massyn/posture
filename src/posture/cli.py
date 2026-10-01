"""``posturecollect`` — extract every table from every registered posture
collector and write it to parquet.

    posturecollect
    posturecollect --include crowdstrike endoflife
    posturecollect --include crowdstrike.hosts --exclude endoflife
    posturecollect --output ./data --history
    posturecollect --include qualys --debug
    posturecollect --thread 5
    posturecollect --env .env.nonprod

By default, every registered source with all of its required environment
variables set is collected (``catalog(filter="environment")`` — a no-auth
source, e.g. ``endoflife``/``macadmins``, is never picked up here since it
has nothing to check). ``--include`` overrides that entirely: only the named
source(s) are collected, unconditionally — this is the one way to reach a
no-auth source, or to run a single source regardless of what's configured.
``--exclude`` then removes entries from whichever set applies. Both take
``<source>`` or ``<source>.<resource>`` entries, and fall back to the
``POSTURE_INCLUDE``/``POSTURE_EXCLUDE`` environment variables (comma- or
space-separated) — see ``posture._selection``.

Every resource of every selected source is streamed page-by-page
(``Collector.collect_page()``) straight into a parquet file via
``pyarrow.parquet.ParquetWriter``, one row group per page — peak memory is
bounded to a single page, never the whole resource. Each file is written to
a ``.tmp`` sibling and renamed into place only once every page has been
written successfully, so a failure partway through a resource never leaves
a truncated file behind; the previous run's file (if any) is left untouched
in that case.

Output layout under ``--output`` (else the ``POSTURE_OUTPUT`` environment
variable, which can live in ``.env``, else ``./output``), one file per
``<source>_<resource>``:

- default: ``<output>/<source>_<resource>.parquet`` (overwritten every run)
- ``--history`` (or ``POSTURE_HISTORY=true``):
  ``<output>/<source>_<resource>/<YYYY.MM.DD>.parquet`` (one
  dated snapshot per day, overwritten if run again the same day)

A failure on one source or resource is logged and does not stop the rest of
the run — ``main()`` returns a non-zero exit code if anything failed, so a
scheduler can still detect a partial run without losing the sources that
did succeed.

Sources are collected concurrently, ``--thread`` (else the
``POSTURE_THREAD`` environment variable, else 3) at a time —
each source gets its own ``CCM`` instance and writes only to its own
``<source>_<resource>.parquet`` file(s), so sources share no mutable state
and can safely run in parallel. Resources within one source are still
collected serially.

Credentials and other settings come from environment variables, loaded from
``.env`` (searched for from the current directory upwards) when ``posture`` is
imported. ``--env PATH`` uses that file instead: every variable the default
``.env`` set is removed before ``PATH`` is loaded, so a source configured
only in ``.env`` isn't silently collected during, say, a non-production run.
Variables already set in the shell still take precedence over either file.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq
from dotenv import load_dotenv

import posture
from posture import CCM
from posture._selection import select_tables, split_list
from posture.exceptions import PostureError
from posture.storage.parquet import arrow_schema

logger = logging.getLogger("posture.cli")

_ARG_FLAGS = {
    "include": "--include",
    "exclude": "--exclude",
    "output": "--output",
    "history": "--history",
    "debug": "--debug",
    "thread": "--thread",
    "env": "--env",
}

_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}


def _env_bool(env_var: str, value: str) -> bool:
    """Parse a boolean environment variable, case-insensitively. Anything
    outside the accepted spellings exits rather than silently guessing."""
    lowered = value.strip().lower()
    if lowered in _TRUE_VALUES:
        return True
    if lowered in _FALSE_VALUES:
        return False
    raise SystemExit(
        f"{env_var}={value!r} is not a boolean — use one of "
        f"{', '.join(sorted(_TRUE_VALUES | _FALSE_VALUES))}"
    )


def _env_positive_int(env_var: str, value: str) -> int:
    """Parse a positive integer environment variable, exiting on anything
    else rather than silently falling back to the default."""
    try:
        number = int(value.strip())
    except ValueError:
        number = 0
    if number < 1:
        raise SystemExit(f"{env_var}={value!r} is not a positive integer")
    return number


#: Arguments that fall back to an environment variable (which may come from
#: .env or --env's file) before their built-in default: name -> (env var,
#: default, parser for the variable's string value). Resolved after --env has
#: swapped the env file in.
_ENV_DEFAULTS: dict[str, tuple[str, Any, Any]] = {
    "include": ("POSTURE_INCLUDE", None, split_list),
    "exclude": ("POSTURE_EXCLUDE", None, split_list),
    "output": ("POSTURE_OUTPUT", "output", lambda _var, value: value),
    "history": ("POSTURE_HISTORY", False, _env_bool),
    "thread": ("POSTURE_THREAD", 3, _env_positive_int),
}


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="posturecollect", description=__doc__.split("\n\n", 1)[0]
    )
    parser.add_argument(
        "--include",
        nargs="+",
        metavar="SOURCE[.RESOURCE]",
        default=None,
        help=(
            "only collect these source(s) or source.resource table(s), "
            "regardless of environment variables — the one way to reach a "
            "no-auth source (default: $POSTURE_INCLUDE)"
        ),
    )
    parser.add_argument(
        "--exclude",
        nargs="+",
        metavar="SOURCE[.RESOURCE]",
        default=None,
        help=(
            "skip these source(s) or source.resource table(s) "
            "(default: $POSTURE_EXCLUDE)"
        ),
    )
    parser.add_argument(
        "--output",
        default=None,
        metavar="PATH",
        help=(
            "directory to write parquet files into (default: $POSTURE_OUTPUT, "
            "else ./output)"
        ),
    )
    parser.add_argument(
        "--history",
        action=argparse.BooleanOptionalAction,
        default=None,
        help=(
            "write one dated file per table per day "
            "(<output>/<table>/<YYYY.MM.DD>.parquet) instead of "
            "overwriting a single <output>/<table>.parquet "
            "(default: $POSTURE_HISTORY, else off; --no-history overrides it)"
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
        default=None,
        metavar="N",
        help=(
            "number of sources to collect concurrently "
            "(default: $POSTURE_THREAD, else 3)"
        ),
    )
    parser.add_argument(
        "--env",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "load environment variables from this file instead of the "
            "default .env (e.g. .env.nonprod)"
        ),
    )
    return parser.parse_args(argv)


def _use_env_file(path: Path) -> None:
    """Replace the variables posture auto-loaded from ``.env`` on import with
    those from ``path`` (see module docstring)."""
    if not path.is_file():
        raise SystemExit(f"--env file not found: {path}")
    for key in posture._DOTENV_KEYS:
        os.environ.pop(key, None)
    load_dotenv(path)


def _log_parameters(args: argparse.Namespace, argv: list[str] | None) -> None:
    """Log every resolved parameter, tagging each as explicitly passed or
    defaulted — helpful when debugging a run without re-reading the
    command line that kicked it off."""
    raw_argv = sys.argv[1:] if argv is None else argv
    for name, value in vars(args).items():
        flag = _ARG_FLAGS.get(name)
        env_var = _ENV_DEFAULTS[name][0] if name in _ENV_DEFAULTS else None
        # A BooleanOptionalAction flag's --no- form counts as explicit too.
        if flag and (flag in raw_argv or f"--no-{flag[2:]}" in raw_argv):
            origin = "explicit"
        elif env_var and os.environ.get(env_var):
            origin = f"environment {env_var}"
        else:
            origin = "default"
        logger.info("parameter %s = %r (%s)", name, value, origin)


def _apply_env_defaults(args: argparse.Namespace) -> None:
    """Fill each ``_ENV_DEFAULTS`` argument not passed on the command line
    from its environment variable, else its built-in default."""
    for name, (env_var, default, parse) in _ENV_DEFAULTS.items():
        if getattr(args, name) is None:
            value = os.environ.get(env_var)
            setattr(args, name, parse(env_var, value) if value else default)


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

    The file schema takes declared columns' types from the manifest, not the
    first page's dtypes — see ``arrow_schema``.
    """
    column_types = ccm.column_types(resource)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    writer: pq.ParquetWriter | None = None
    record_count = 0
    try:
        for page in ccm.collect_page(resource):
            if writer is None:
                writer = pq.ParquetWriter(tmp_path, arrow_schema(page, column_types))
            table = pa.Table.from_pandas(
                page, schema=writer.schema, preserve_index=False
            )
            writer.write_table(table)
            record_count += len(page)
    finally:
        if writer is not None:
            writer.close()
    if writer is not None:
        tmp_path.replace(path)
    return record_count


def _collect_source(
    source: str, resources: list[str], output_dir: Path, *, history: bool
) -> list[dict[str, Any]]:
    """Collect ``resources`` of one source, returning one result dict per
        table (``table``, ``records``, ``seconds`` — wall-clock time spent on that
    table, failed or not — and ``status``, "ok" or "failed: <reason>").

        Called from its own thread when ``--thread`` > 1 — each source gets its
        own ``CCM`` instance and writes only to its own ``<source>_<resource>``
        file(s), so sources share no mutable state and can run concurrently.
    """
    try:
        ccm = CCM(source)
    except (PostureError, ValueError) as exc:
        logger.exception("%s: skipped", source)
        return [
            {"table": source, "records": 0, "seconds": 0.0, "status": f"failed: {exc}"}
        ]

    results: list[dict[str, Any]] = []
    for resource in resources:
        stem = f"{source}_{resource}"
        path = _output_path(output_dir, stem, history=history)
        logger.info("%s.%s: collecting", source, resource)
        started = time.monotonic()
        try:
            record_count = _collect_resource(ccm, resource, path)
        except PostureError as exc:
            seconds = time.monotonic() - started
            logger.exception("%s.%s: failed after %.1fs", source, resource, seconds)
            results.append(
                {
                    "table": stem,
                    "records": 0,
                    "seconds": seconds,
                    "status": f"failed: {exc}",
                }
            )
            continue
        seconds = time.monotonic() - started
        logger.info(
            "%s.%s: %d record(s) written to %s in %.1fs",
            source,
            resource,
            record_count,
            path,
            seconds,
        )
        results.append(
            {"table": stem, "records": record_count, "seconds": seconds, "status": "ok"}
        )
    return results


def _log_summary(results: list[dict[str, Any]]) -> None:
    """Log a summary table of every table collected this run, in the same
    order sources were submitted, so a run's end state is visible without
    scrolling back through the per-page log lines above it."""
    if not results:
        return
    table_width = max(len(r["table"]) for r in results)
    status_width = max(len(r["status"]) for r in results)
    header = (
        f"{'Table':<{table_width}}  {'Records':>10}  {'Seconds':>9}  "
        f"{'Status':<{status_width}}"
    )
    logger.info("Summary:")
    logger.info(header)
    logger.info("-" * len(header))
    for r in results:
        logger.info(
            f"{r['table']:<{table_width}}  {r['records']:>10}  {r['seconds']:>9.1f}  "
            f"{r['status']:<{status_width}}"
        )


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        force=True,
    )
    if args.env is not None:
        _use_env_file(args.env)
    _apply_env_defaults(args)
    _log_parameters(args, argv)

    output_dir = Path(args.output)
    sources = select_tables(args.include, args.exclude)

    if not sources:
        logger.warning(
            "No sources to collect — set the required environment "
            "variable(s) for a source, or check --include/--exclude"
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
                _collect_source, source, resources, output_dir, history=args.history
            ): source
            for source, resources in sources.items()
        }
        for future, source in futures.items():
            try:
                all_results.extend(future.result())
            except Exception as exc:
                logger.exception("%s: unhandled error", source)
                all_results.append(
                    {
                        "table": source,
                        "records": 0,
                        "seconds": 0.0,
                        "status": f"failed: {exc}",
                    }
                )

    _log_summary(all_results)
    had_failure = any(r["status"] != "ok" for r in all_results)
    return 1 if had_failure else 0


if __name__ == "__main__":
    raise SystemExit(main())
