"""Resolve which ``source -> resources`` ``posturecollect`` collects, from its
include/exclude lists.

Each entry is ``<source>`` (every resource of that source) or
``<source>.<resource>`` (just that one). With no include list, the starting
set is every source with its required environment variables set
(``catalog(filter="environment")``); an include list replaces that entirely
and bypasses the environment check. The exclude list is then subtracted from
whichever starting set applies, and a source left with no resources is
dropped. Any entry naming an unknown source or resource exits rather than
being silently ignored.
"""

from __future__ import annotations

import re
from typing import Any

from posture import catalog

#: ``source -> resources``, where ``None`` means every resource of the source.
_Spec = dict[str, set[str] | None]


def split_list(_env_var: str, value: str) -> list[str]:
    """Parse a comma- and/or whitespace-separated environment variable value
    into a list (the ``_ENV_DEFAULTS`` parser signature)."""
    return [item for item in re.split(r"[,\s]+", value) if item]


def _parse_entries(flag: str, entries: list[str], all_sources: dict[str, Any]) -> _Spec:
    spec: _Spec = {}
    unknown: list[str] = []
    for entry in entries:
        source, _, resource = entry.partition(".")
        if source not in all_sources or (
            resource and resource not in all_sources[source]["resources"]
        ):
            unknown.append(entry)
            continue
        if not resource:
            spec[source] = None
        elif spec.get(source, set()) is not None:
            spec.setdefault(source, set()).add(resource)
    if unknown:
        raise SystemExit(
            f"Unknown {flag} entr{'y' if len(unknown) == 1 else 'ies'}: "
            f"{', '.join(unknown)}. Use <source> or <source>.<resource>; "
            f"available sources: {', '.join(sorted(all_sources))}"
        )
    return spec


def select_tables(
    include: list[str] | None, exclude: list[str] | None
) -> dict[str, list[str]]:
    """Return ``source -> resources`` to collect, per the module docstring."""
    all_sources = catalog()
    excluded = _parse_entries("--exclude", exclude or [], all_sources)
    if include is None:
        included: _Spec = dict.fromkeys(catalog(filter="environment"))
    else:
        included = _parse_entries("--include", include, all_sources)

    tables: dict[str, list[str]] = {}
    for source, wanted in included.items():
        if source in excluded and excluded[source] is None:
            continue
        dropped = excluded.get(source) or set()
        resources = [
            resource
            for resource in all_sources[source]["resources"]
            if (wanted is None or resource in wanted) and resource not in dropped
        ]
        if resources:
            tables[source] = resources
    return tables
