"""The ``posturecollect`` listings that describe a run without collecting
anything: ``--catalog`` (the tables posture offers), ``--variables`` (the
environment variables each source reads), ``--schema`` (one table's columns)
and ``--dry-run`` (the tables a real run would collect).

Each returns the lines to print. All but ``schema_lines`` take the
``source -> resources`` selection ``cli.main`` resolved from
``--include``/``--exclude``. Reading the
environment is the only side effect: no collector is instantiated and no
request is sent. Variable values are never shown, only whether each is set,
since most of them are credentials.
"""

from __future__ import annotations

import os
from typing import Any

from posture import catalog


def _source_status(info: dict[str, Any]) -> str:
    required = info["required_config"].values()
    if not required:
        return "no credentials needed"
    missing = [env_var for env_var in required if env_var not in os.environ]
    return f"missing {', '.join(missing)}" if missing else "configured"


def catalog_lines(tables: dict[str, list[str]]) -> list[str]:
    """Each selected source, with its display name and environment status,
    followed by its tables."""
    sources = catalog()
    lines: list[str] = []
    for source, resources in sorted(tables.items()):
        info = sources[source]
        lines.append(f"{source} ({info['display_name']}): {_source_status(info)}")
        lines.extend(f"  {source}.{resource}" for resource in resources)
    return lines


def variables_lines(tables: dict[str, list[str]]) -> list[str]:
    """Each selected source's required and optional environment variables,
    and whether each is set."""
    sources = catalog()
    lines: list[str] = []
    for source in sorted(tables):
        info = sources[source]
        lines.append(f"{source} ({info['display_name']})")
        variables = [
            ("required", env_var) for env_var in info["required_config"].values()
        ] + [("optional", env_var) for env_var in info["optional_config"].values()]
        if not variables:
            lines.append("  no environment variables")
            continue
        width = max(len(env_var) for _, env_var in variables)
        for kind, env_var in variables:
            state = "set" if env_var in os.environ else "not set"
            lines.append(f"  {kind}  {env_var:<{width}}  {state}")
    return lines


def schema_lines(table: str) -> list[str]:
    """The columns and declared types of one ``source.resource`` table."""
    source, _, resource = table.partition(".")
    sources = catalog()
    if source not in sources or resource not in sources[source]["resources"]:
        raise SystemExit(
            f"Unknown --schema table: {table}. Use <source>.<resource>, e.g. "
            f"crowdstrike.hosts; --catalog lists them"
        )
    column_types = sources[source]["resources"][resource]["column_types"]
    width = max((len(column) for column in column_types), default=0)
    return [f"{table} ({sources[source]['display_name']})"] + [
        f"  {column:<{width}}  {column_type}"
        for column, column_type in column_types.items()
    ]


def dry_run_lines(tables: dict[str, list[str]]) -> list[str]:
    """One ``source.resource`` line per table a real run would collect."""
    return [
        f"{source}.{resource}"
        for source, resources in sorted(tables.items())
        for resource in resources
    ]
