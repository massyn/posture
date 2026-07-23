"""Manifest-driven parsing: raw API records + manifest in, DataFrame out.

Pure function boundary — no network calls, no state, no side effects beyond
logging coercion warnings. Fully testable with fixture JSON and zero mocked
HTTP.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

import pandas as pd

logger = logging.getLogger("posture.parse")

_VALID_TYPES = {"str", "int", "float", "bool", "datetime", "json"}
_PARENT_PREFIX = "$parent."
_LITERAL_PREFIX = "$literal:"

_TRUE_STRINGS = {"true", "1", "yes", "y"}
_FALSE_STRINGS = {"false", "0", "no", "n"}


def parse(
    raw_records: list[dict[str, Any]],
    manifest: dict[str, Any],
    *,
    resource: str = "",
) -> pd.DataFrame:
    """Parse raw records into a complete DataFrame per the declared manifest.

    Top-level resources iterate raw_records directly. Derived resources
    declare a ``record_path`` and explode each parent's nested list into its
    own rows, with ``$parent.<path>`` columns pulling from the parent record.
    Grain is sacred: a parent with zero matching children yields zero rows
    for that parent, never a null-padded row.
    """
    columns: dict[str, tuple] = manifest["columns"]
    record_path = manifest.get("record_path")
    column_names = list(columns.keys())

    rows: list[dict[str, Any]] = []
    if record_path is None:
        for record in raw_records:
            rows.append(_build_row(record, None, columns, resource))
    else:
        for parent in raw_records:
            children = _get_path(parent, record_path)
            if not children:
                continue
            for child in children:
                rows.append(_build_row(child, parent, columns, resource))

    if not rows:
        df = pd.DataFrame(columns=column_names)
    else:
        df = pd.DataFrame(rows, columns=column_names)

    for name, spec in columns.items():
        if spec[1] == "datetime":
            df[name] = pd.to_datetime(df[name], utc=True).astype("datetime64[ns, UTC]")
    return df


def _build_row(
    record: dict[str, Any] | None,
    parent: dict[str, Any] | None,
    columns: dict[str, tuple],
    resource: str,
) -> dict[str, Any]:
    row: dict[str, Any] = {}
    for name, spec in columns.items():
        path, type_name = spec[0], spec[1]
        hints = spec[2] if len(spec) > 2 else {}
        if path.startswith(_PARENT_PREFIX):
            value = _get_path(parent, path[len(_PARENT_PREFIX) :])
        elif path.startswith(_LITERAL_PREFIX):
            value = path[len(_LITERAL_PREFIX) :]
        else:
            value = _get_path(record, path)
        row[name] = _coerce(
            value, type_name, resource=resource, column=name, hints=hints
        )
    return row


def _get_path(record: dict[str, Any] | None, path: str) -> Any:
    if record is None:
        return None
    node: Any = record
    for key in path.split("."):
        if isinstance(node, list):
            if not key.isdigit() or int(key) >= len(node):
                return None
            node = node[int(key)]
        elif isinstance(node, dict):
            node = node.get(key)
        else:
            return None
        if node is None:
            return None
    return node


def _coerce(
    value: Any, type_name: str, *, resource: str, column: str, hints: dict[str, Any]
) -> Any:
    if type_name not in _VALID_TYPES:
        raise ValueError(f"Unknown column type '{type_name}' for {resource}.{column}")
    if value is None:
        return pd.NaT if type_name == "datetime" else None
    if type_name == "str":
        return str(value)
    if type_name == "int":
        return _coerce_int(value, resource, column)
    if type_name == "float":
        return _coerce_float(value, resource, column)
    if type_name == "bool":
        return _coerce_bool(value, resource, column)
    if type_name == "datetime":
        return _coerce_datetime(value, resource, column, hints)
    return json.dumps(value)  # json


def _coerce_int(value: Any, resource: str, column: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        logger.warning("Unparseable int for %s.%s: sample=%r", resource, column, value)
        return None


def _coerce_float(value: Any, resource: str, column: str) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        logger.warning(
            "Unparseable float for %s.%s: sample=%r", resource, column, value
        )
        return None


def _coerce_bool(value: Any, resource: str, column: str) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in _TRUE_STRINGS:
            return True
        if lowered in _FALSE_STRINGS:
            return False
    logger.warning("Unparseable bool for %s.%s: sample=%r", resource, column, value)
    return None


def _coerce_datetime(
    value: Any, resource: str, column: str, hints: dict[str, Any]
) -> pd.Timestamp:
    parsed: pd.Timestamp | None = None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        parsed = _parse_epoch(value)
    else:
        text = str(value)
        parsed = _parse_iso(text)
        if parsed is None and "format" in hints:
            parsed = _parse_with_format(text, hints["format"])

    if parsed is not None and not (
        pd.Timestamp.min.tz_localize("UTC")
        <= parsed
        <= pd.Timestamp.max.tz_localize("UTC")
    ):
        logger.warning(
            "Out-of-range datetime for %s.%s: sample=%r", resource, column, value
        )
        return pd.NaT

    if parsed is None:
        logger.warning(
            "Unparseable datetime for %s.%s: sample=%r", resource, column, value
        )
        return pd.NaT
    return parsed


def _parse_epoch(value: float) -> pd.Timestamp | None:
    try:
        magnitude = len(str(int(abs(value))))
        if magnitude >= 16:
            seconds = value / 1_000_000
        elif magnitude >= 13:
            seconds = value / 1_000
        elif magnitude >= 10:
            seconds = value
        else:
            return None
        return pd.Timestamp(seconds, unit="s", tz="UTC")
    except (ValueError, OverflowError):
        return None


def _parse_iso(value: str) -> pd.Timestamp | None:
    try:
        ts = pd.Timestamp(value)
    except (ValueError, TypeError):
        return None
    if ts.tzinfo is None:
        return ts.tz_localize("UTC")
    return ts.tz_convert("UTC")


def _parse_with_format(value: str, fmt: str) -> pd.Timestamp | None:
    try:
        dt = datetime.strptime(value, fmt)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return pd.Timestamp(dt).tz_convert("UTC")
