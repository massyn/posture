"""``schema=`` on the table backends: declared column types instead of
dtype inference, so an all-null column doesn't change SQL type between runs.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import duckdb
import pandas as pd
import pytest

from posture import CCM
from posture.exceptions import ResourceUnknown
from posture.storage import open_storage, write_storage
from posture.storage.base import resolve_sql_type

_BOOL_MAP = {"bool": "BOOLEAN", "str": "TEXT"}


def _infer(_series: pd.Series) -> str:
    return "INFERRED"


def test_resolve_sql_type_prefers_declared_schema() -> None:
    s = pd.Series([None, None], dtype=object)
    assert resolve_sql_type("flag", s, {"flag": "bool"}, _BOOL_MAP, _infer) == "BOOLEAN"


def test_resolve_sql_type_falls_back_when_column_absent() -> None:
    s = pd.Series([None, None], dtype=object)
    assert (
        resolve_sql_type("other", s, {"flag": "bool"}, _BOOL_MAP, _infer) == "INFERRED"
    )


def test_resolve_sql_type_falls_back_on_none_schema() -> None:
    s = pd.Series([1, 2])
    assert resolve_sql_type("flag", s, None, _BOOL_MAP, _infer) == "INFERRED"


def test_resolve_sql_type_falls_back_on_unknown_type_name() -> None:
    s = pd.Series([None, None], dtype=object)
    assert resolve_sql_type("flag", s, {"flag": "geometry"}, _BOOL_MAP, _infer) == (
        "INFERRED"
    )


def _bool_col_type_sqlite(db_path: Path, table: str, column: str) -> str:
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(f'PRAGMA table_info("{table}")').fetchall()
    finally:
        conn.close()
    return next(r[2] for r in rows if r[1] == column)


def _col_type_duckdb(db_path: Path, table: str, column: str) -> str:
    conn = duckdb.connect(str(db_path))
    try:
        return conn.execute(
            "SELECT data_type FROM information_schema.columns "
            "WHERE table_name = ? AND column_name = ?",
            [table, column],
        ).fetchone()[0]
    finally:
        conn.close()


def test_sqlite_all_null_bool_uses_declared_type(tmp_path: Path) -> None:
    db_path = tmp_path / "posture.db"
    schema = {"a": "int", "is_resource_account": "bool"}
    first = pd.DataFrame({"a": [1, 2], "is_resource_account": [None, None]})

    write_storage(
        first,
        "sqlite",
        "users",
        config={"path": str(db_path)},
        mode="truncate",
        schema=schema,
    )
    assert _bool_col_type_sqlite(db_path, "users", "is_resource_account") == "BOOLEAN"

    # A later write with a real boolean must not have provoked a type change.
    second = pd.DataFrame({"a": [3], "is_resource_account": [True]})
    write_storage(
        second,
        "sqlite",
        "users",
        config={"path": str(db_path)},
        mode="append",
        schema=schema,
    )
    assert _bool_col_type_sqlite(db_path, "users", "is_resource_account") == "BOOLEAN"

    conn = sqlite3.connect(db_path)
    try:
        got = conn.execute(
            "SELECT is_resource_account FROM users ORDER BY a"
        ).fetchall()
    finally:
        conn.close()
    assert got == [(None,), (None,), (1,)]


def test_duckdb_all_null_bool_uses_declared_type(tmp_path: Path) -> None:
    db_path = tmp_path / "posture.duckdb"
    schema = {"a": "int", "is_resource_account": "bool"}

    write_storage(
        pd.DataFrame({"a": [1], "is_resource_account": [None]}),
        "duckdb",
        "users",
        config={"path": str(db_path)},
        mode="truncate",
        schema=schema,
    )
    assert _col_type_duckdb(db_path, "users", "is_resource_account") == "BOOLEAN"

    write_storage(
        pd.DataFrame({"a": [2], "is_resource_account": [True]}),
        "duckdb",
        "users",
        config={"path": str(db_path)},
        mode="append",
        schema=schema,
    )
    conn = duckdb.connect(str(db_path))
    try:
        got = conn.execute(
            "SELECT is_resource_account FROM users ORDER BY a"
        ).fetchall()
    finally:
        conn.close()
    assert got == [(None,), (True,)]


def test_duckdb_without_schema_all_null_object_still_falls_back(tmp_path: Path) -> None:
    # Contrast: no schema -> inference. An all-null object column is VARCHAR
    # (the pre-existing fallback), i.e. the behaviour is unchanged when the
    # new argument is omitted.
    db_path = tmp_path / "posture.duckdb"
    write_storage(
        pd.DataFrame({"a": [1], "maybe": [None]}),
        "duckdb",
        "t",
        config={"path": str(db_path)},
        mode="truncate",
    )
    assert _col_type_duckdb(db_path, "t", "maybe") == "VARCHAR"


def test_duckdb_schema_applied_to_later_added_column(tmp_path: Path) -> None:
    db_path = tmp_path / "posture.duckdb"
    write_storage(
        pd.DataFrame({"a": [1]}),
        "duckdb",
        "t",
        config={"path": str(db_path)},
        mode="truncate",
    )
    write_storage(
        pd.DataFrame({"a": [2], "added": [None]}),
        "duckdb",
        "t",
        config={"path": str(db_path)},
        mode="append",
        schema={"added": "bool"},
    )
    assert _col_type_duckdb(db_path, "t", "added") == "BOOLEAN"


def test_file_backend_accepts_and_ignores_schema(tmp_path: Path) -> None:
    # csv has no typed columns; passing schema must not error.
    write_storage(
        pd.DataFrame({"a": [1]}),
        "csv",
        "t",
        config={"path": str(tmp_path)},
        schema={"a": "int"},
    )
    store = open_storage("csv", {"path": str(tmp_path)})
    store.write_page(pd.DataFrame({"a": [2]}), "t2", schema={"a": "int"})
    assert (tmp_path / "default" / "t.csv").exists()


def test_column_types_reads_manifest_plus_collected_at() -> None:
    ccm = CCM("http")
    types = ccm.column_types("headers")

    assert types["ok"] == "bool"
    assert types["status_code"] == "int"
    assert types["host"] == "str"
    assert types["_collected_at"] == "datetime"


def test_column_types_unknown_resource_raises() -> None:
    with pytest.raises(ResourceUnknown):
        CCM("http").column_types("nope")
