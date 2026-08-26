from __future__ import annotations

import os
import uuid

import pandas as pd
import psycopg
import pytest

from posture.storage import PostgresStorage, write_storage

_DSN = os.environ.get(
    "POSTURE_TEST_POSTGRES_DSN",
    "postgresql://postgres:postgres@localhost:5432/postgres",
)


def _server_available() -> bool:
    try:
        with psycopg.connect(_DSN, connect_timeout=2):
            return True
    except psycopg.OperationalError:
        return False


pytestmark = pytest.mark.skipif(
    not _server_available(), reason="no Postgres server reachable for integration test"
)

_DF = pd.DataFrame({"a": [1, 2], "b": ["x", "y"]})


@pytest.fixture
def table_name() -> str:
    name = f"posture_test_{uuid.uuid4().hex[:8]}"
    yield name
    with psycopg.connect(_DSN) as conn, conn.cursor() as cur:
        cur.execute(f'DROP TABLE IF EXISTS "{name}"')


def _read(name: str) -> pd.DataFrame:
    with psycopg.connect(_DSN) as conn:
        return pd.read_sql(f'SELECT * FROM "{name}" ORDER BY a', conn)


def test_write_storage_postgres_truncate(table_name: str) -> None:
    write_storage(_DF, "postgres", table_name, config={"dsn": _DSN}, mode="truncate")
    result = _read(table_name)
    assert list(result["a"]) == [1, 2]
    assert list(result["b"]) == ["x", "y"]
    assert (result["tenancy"] == "default").all()


def test_write_storage_postgres_truncate_replaces_current_tenancy(
    table_name: str,
) -> None:
    write_storage(_DF, "postgres", table_name, config={"dsn": _DSN}, mode="truncate")
    smaller = pd.DataFrame({"a": [9], "b": ["z"]})
    write_storage(
        smaller, "postgres", table_name, config={"dsn": _DSN}, mode="truncate"
    )
    result = _read(table_name)
    assert list(result["a"]) == [9]


def test_write_storage_postgres_truncate_only_clears_current_tenancy(
    table_name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TENANCY", "acme")
    write_storage(_DF, "postgres", table_name, config={"dsn": _DSN}, mode="truncate")

    monkeypatch.setenv("TENANCY", "other")
    write_storage(_DF, "postgres", table_name, config={"dsn": _DSN}, mode="truncate")

    monkeypatch.setenv("TENANCY", "acme")
    smaller = pd.DataFrame({"a": [9], "b": ["z"]})
    write_storage(
        smaller, "postgres", table_name, config={"dsn": _DSN}, mode="truncate"
    )

    result = _read(table_name)
    assert len(result) == 3  # 1 "acme" row (replaced) + 2 "other" rows (untouched)
    assert set(result["tenancy"]) == {"acme", "other"}


def test_write_storage_postgres_append(table_name: str) -> None:
    write_storage(_DF, "postgres", table_name, config={"dsn": _DSN}, mode="truncate")
    more = pd.DataFrame({"a": [3], "b": ["z"]})
    write_storage(more, "postgres", table_name, config={"dsn": _DSN}, mode="append")
    result = _read(table_name)
    assert len(result) == 3


def test_postgres_adds_new_column_to_existing_table(table_name: str) -> None:
    write_storage(_DF, "postgres", table_name, config={"dsn": _DSN}, mode="truncate")
    wider = _DF.copy()
    wider["c"] = ["p", "q"]
    write_storage(wider, "postgres", table_name, config={"dsn": _DSN}, mode="truncate")
    result = _read(table_name)
    assert list(result["c"]) == ["p", "q"]


def test_postgres_warns_on_missing_column(
    table_name: str, caplog: pytest.LogCaptureFixture
) -> None:
    write_storage(_DF, "postgres", table_name, config={"dsn": _DSN}, mode="truncate")
    narrower = _DF[["a"]]
    with caplog.at_level("WARNING"):
        write_storage(
            narrower, "postgres", table_name, config={"dsn": _DSN}, mode="truncate"
        )
    assert any("'b'" in record.getMessage() for record in caplog.records)


def test_write_page_truncate_first_page_only(table_name: str) -> None:
    store = PostgresStorage({"dsn": _DSN})
    store.write_page(_DF, table_name, mode="truncate")
    store.write_page(_DF, table_name, mode="truncate")
    result = _read(table_name)
    assert len(result) == 4


def test_write_storage_postgres_discrete_keys(table_name: str) -> None:
    conn_info = psycopg.conninfo.conninfo_to_dict(_DSN)
    config = {
        "host": conn_info.get("host", "localhost"),
        "port": str(conn_info.get("port", 5432)),
        "dbname": conn_info["dbname"],
        "user": conn_info["user"],
        "password": conn_info.get("password", ""),
    }
    write_storage(_DF, "postgres", table_name, config=config, mode="truncate")
    result = _read(table_name)
    assert len(result) == 2
