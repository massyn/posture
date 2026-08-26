from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import duckdb
import pandas as pd
import pytest

from posture.exceptions import PostureError, StorageConfigError, StorageWriteError
from posture.storage import (
    BigQueryStorage,
    CsvStorage,
    DuckdbStorage,
    GcsStorage,
    JsonStorage,
    ParquetStorage,
    PostgresStorage,
    S3Storage,
    SnowflakeStorage,
    SqliteStorage,
    Storage,
    StorageBackend,
    storage_catalog,
    write_storage,
)

_DF = pd.DataFrame({"a": [1, 2], "b": ["x", "y"]})


@pytest.mark.parametrize(
    "backend_cls",
    [
        CsvStorage,
        JsonStorage,
        ParquetStorage,
        SqliteStorage,
        DuckdbStorage,
        PostgresStorage,
        GcsStorage,
        S3Storage,
        BigQueryStorage,
        SnowflakeStorage,
    ],
)
def test_backend_satisfies_storage_backend_protocol(backend_cls: type) -> None:
    assert issubclass(backend_cls, StorageBackend)


def test_write_storage_default_mode_is_truncate(tmp_path: Path) -> None:
    write_storage(_DF, "csv", "hosts", config={"path": str(tmp_path)})
    assert (tmp_path / "default" / "hosts.csv").exists()
    today = datetime.now(timezone.utc).date()
    assert not (
        tmp_path / "default" / "hosts" / f"{today:%Y}" / f"{today:%m}" / f"{today:%d}"
    ).exists()


def test_write_storage_csv_truncate(tmp_path: Path) -> None:
    write_storage(_DF, "csv", "hosts", config={"path": str(tmp_path)}, mode="truncate")
    out = tmp_path / "default" / "hosts.csv"
    assert out.exists()
    assert not out.with_suffix(".csv.tmp").exists()
    result = pd.read_csv(out)
    assert result.drop(columns=["upload_timestamp"]).equals(_DF)
    assert result["upload_timestamp"].notna().all()


def test_write_storage_csv_truncate_overwrites(tmp_path: Path) -> None:
    write_storage(_DF, "csv", "hosts", config={"path": str(tmp_path)}, mode="truncate")
    smaller = pd.DataFrame({"a": [9], "b": ["z"]})
    write_storage(
        smaller, "csv", "hosts", config={"path": str(tmp_path)}, mode="truncate"
    )
    out = tmp_path / "default" / "hosts.csv"
    result = pd.read_csv(out)
    assert result.drop(columns=["upload_timestamp"]).equals(smaller)


def test_write_storage_csv_append_is_dated(tmp_path: Path) -> None:
    write_storage(_DF, "csv", "hosts", config={"path": str(tmp_path)}, mode="append")
    today = datetime.now(timezone.utc).date()
    out = (
        tmp_path
        / "default"
        / "hosts"
        / f"{today:%Y}"
        / f"{today:%m}"
        / f"{today:%d}"
        / "hosts.csv"
    )
    assert out.exists()
    result = pd.read_csv(out)
    assert result.drop(columns=["upload_timestamp"]).equals(_DF)


def test_write_storage_csv_tenancy_env_var(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TENANCY", "acme")
    write_storage(_DF, "csv", "hosts", config={"path": str(tmp_path)}, mode="truncate")
    assert (tmp_path / "acme" / "hosts.csv").exists()


def test_write_storage_json(tmp_path: Path) -> None:
    write_storage(_DF, "json", "hosts", config={"path": str(tmp_path)}, mode="truncate")
    out = tmp_path / "default" / "hosts.json"
    records = json.loads(out.read_text())
    for record in records:
        del record["upload_timestamp"]
    assert records == [{"a": 1, "b": "x"}, {"a": 2, "b": "y"}]


def test_write_storage_parquet(tmp_path: Path) -> None:
    write_storage(
        _DF, "parquet", "hosts", config={"path": str(tmp_path)}, mode="truncate"
    )
    out = tmp_path / "default" / "hosts.parquet"
    result = pd.read_parquet(out)
    assert result.drop(columns=["upload_timestamp"]).equals(_DF)


def test_write_storage_invalid_mode(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Invalid mode"):
        write_storage(_DF, "csv", "hosts", config={"path": str(tmp_path)}, mode="bogus")


def test_write_storage_missing_path_raises() -> None:
    with pytest.raises(ValueError, match="Missing required config 'path'"):
        write_storage(_DF, "csv", "hosts", config={})


def test_invalid_mode_is_storage_config_error_and_posture_error(tmp_path: Path) -> None:
    with pytest.raises(StorageConfigError) as exc_info:
        write_storage(_DF, "csv", "hosts", config={"path": str(tmp_path)}, mode="bogus")
    assert isinstance(exc_info.value, PostureError)
    assert isinstance(exc_info.value, ValueError)  # backward compatible


def test_missing_config_is_storage_config_error_and_posture_error() -> None:
    with pytest.raises(StorageConfigError) as exc_info:
        write_storage(_DF, "csv", "hosts", config={})
    assert isinstance(exc_info.value, PostureError)
    assert isinstance(exc_info.value, ValueError)  # backward compatible


def test_unknown_backend_is_storage_config_error() -> None:
    with pytest.raises(StorageConfigError):
        write_storage(_DF, "bogus", "hosts", config={})


def test_write_failure_wrapped_as_storage_write_error(tmp_path: Path) -> None:
    # Point sqlite's "path" at a directory that can't hold a db file (a
    # regular file where sqlite needs a parent directory) so connect/write
    # fails with a real driver-level error, not our own validation.
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    db_path = blocker / "sub" / "posture.db"

    with pytest.raises(StorageWriteError) as exc_info:
        write_storage(_DF, "sqlite", "hosts", config={"path": str(db_path)})
    assert isinstance(exc_info.value, PostureError)
    assert exc_info.value.__cause__ is not None


def test_write_page_truncate_clears_prior_run(tmp_path: Path) -> None:
    store = CsvStorage({"path": str(tmp_path)})
    store.write_page(_DF, "hosts", mode="truncate")
    stale = tmp_path / "default" / "hosts" / "stale-leftover.csv"
    stale.write_text("leftover")

    # New run: fresh instance, first page for "hosts" should clear "stale".
    store2 = CsvStorage({"path": str(tmp_path)})
    store2.write_page(_DF, "hosts", mode="truncate")
    files = list((tmp_path / "default" / "hosts").iterdir())
    assert stale not in files
    assert len(files) == 1


def test_upload_timestamp_constant_across_pages_within_run(tmp_path: Path) -> None:
    store = CsvStorage({"path": str(tmp_path)})
    store.write_page(_DF, "hosts", mode="truncate")
    store.write_page(_DF, "hosts", mode="truncate")
    files = list((tmp_path / "default" / "hosts").iterdir())
    timestamps = {pd.read_csv(f)["upload_timestamp"].iloc[0] for f in files}
    assert len(timestamps) == 1


def test_write_page_truncate_accumulates_within_run(tmp_path: Path) -> None:
    store = CsvStorage({"path": str(tmp_path)})
    store.write_page(_DF, "hosts", mode="truncate")
    store.write_page(_DF, "hosts", mode="truncate")
    files = list((tmp_path / "default" / "hosts").iterdir())
    assert len(files) == 2


def test_write_page_append_never_clears(tmp_path: Path) -> None:
    store = CsvStorage({"path": str(tmp_path)})
    store.write_page(_DF, "hosts", mode="append")
    today = datetime.now(timezone.utc).date()
    page_dir = (
        tmp_path / "default" / "hosts" / f"{today:%Y}" / f"{today:%m}" / f"{today:%d}"
    )
    assert len(list(page_dir.iterdir())) == 1

    store2 = CsvStorage({"path": str(tmp_path)})
    store2.write_page(_DF, "hosts", mode="append")
    assert len(list(page_dir.iterdir())) == 2


def test_write_page_tenancy_env_var(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TENANCY", "acme")
    store = CsvStorage({"path": str(tmp_path)})
    store.write_page(_DF, "hosts", mode="truncate")
    files = list((tmp_path / "acme" / "hosts").iterdir())
    assert len(files) == 1


def test_sqlite_truncate_then_append(tmp_path: Path) -> None:
    db_path = tmp_path / "posture.db"
    write_storage(
        _DF, "sqlite", "hosts", config={"path": str(db_path)}, mode="truncate"
    )
    conn = sqlite3.connect(db_path)
    try:
        result = pd.read_sql("SELECT a, b FROM hosts", conn)
        assert result.equals(_DF)
        assert (
            pd.read_sql("SELECT tenancy FROM hosts", conn)["tenancy"] == "default"
        ).all()
    finally:
        conn.close()

    more = pd.DataFrame({"a": [3], "b": ["z"]})
    write_storage(more, "sqlite", "hosts", config={"path": str(db_path)}, mode="append")
    conn = sqlite3.connect(db_path)
    try:
        result = pd.read_sql("SELECT * FROM hosts", conn)
    finally:
        conn.close()
    assert len(result) == 3


def test_sqlite_truncate_only_clears_current_tenancy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "posture.db"
    monkeypatch.setenv("TENANCY", "acme")
    write_storage(
        _DF, "sqlite", "hosts", config={"path": str(db_path)}, mode="truncate"
    )

    monkeypatch.setenv("TENANCY", "other")
    write_storage(
        _DF, "sqlite", "hosts", config={"path": str(db_path)}, mode="truncate"
    )

    monkeypatch.setenv("TENANCY", "acme")
    smaller = pd.DataFrame({"a": [9], "b": ["z"]})
    write_storage(
        smaller, "sqlite", "hosts", config={"path": str(db_path)}, mode="truncate"
    )

    conn = sqlite3.connect(db_path)
    try:
        result = pd.read_sql("SELECT * FROM hosts ORDER BY tenancy, a", conn)
    finally:
        conn.close()
    assert len(result) == 3  # 1 "acme" row (replaced) + 2 "other" rows (untouched)
    assert set(result["tenancy"]) == {"acme", "other"}


def test_sqlite_adds_new_column_to_existing_table(tmp_path: Path) -> None:
    db_path = tmp_path / "posture.db"
    write_storage(
        _DF, "sqlite", "hosts", config={"path": str(db_path)}, mode="truncate"
    )
    wider = _DF.copy()
    wider["c"] = ["p", "q"]
    write_storage(
        wider, "sqlite", "hosts", config={"path": str(db_path)}, mode="truncate"
    )

    conn = sqlite3.connect(db_path)
    try:
        result = pd.read_sql("SELECT * FROM hosts WHERE c IS NOT NULL", conn)
    finally:
        conn.close()
    assert list(result["c"]) == ["p", "q"]


def test_sqlite_warns_on_missing_column(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    db_path = tmp_path / "posture.db"
    write_storage(
        _DF, "sqlite", "hosts", config={"path": str(db_path)}, mode="truncate"
    )
    narrower = _DF[["a"]]
    with caplog.at_level("WARNING"):
        write_storage(
            narrower, "sqlite", "hosts", config={"path": str(db_path)}, mode="truncate"
        )
    assert any("'b'" in record.getMessage() for record in caplog.records)


def test_sqlite_write_page_truncate_first_page_only(tmp_path: Path) -> None:
    db_path = tmp_path / "posture.db"
    store = SqliteStorage({"path": str(db_path)})
    store.write_page(_DF, "hosts", mode="truncate")
    store.write_page(_DF, "hosts", mode="truncate")
    conn = sqlite3.connect(db_path)
    try:
        result = pd.read_sql("SELECT * FROM hosts", conn)
    finally:
        conn.close()
    assert len(result) == 4


def test_duckdb_truncate_then_append(tmp_path: Path) -> None:
    db_path = tmp_path / "posture.duckdb"
    write_storage(
        _DF, "duckdb", "hosts", config={"path": str(db_path)}, mode="truncate"
    )

    conn = duckdb.connect(str(db_path))
    try:
        result = conn.execute("SELECT a, b FROM hosts").df()
        assert result.equals(_DF)
        tenancies = conn.execute("SELECT DISTINCT tenancy FROM hosts").df()
        assert list(tenancies["tenancy"]) == ["default"]
    finally:
        conn.close()

    more = pd.DataFrame({"a": [3], "b": ["z"]})
    write_storage(more, "duckdb", "hosts", config={"path": str(db_path)}, mode="append")
    conn = duckdb.connect(str(db_path))
    try:
        result = conn.execute("SELECT * FROM hosts").df()
    finally:
        conn.close()
    assert len(result) == 3


def test_duckdb_truncate_only_clears_current_tenancy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "posture.duckdb"
    monkeypatch.setenv("TENANCY", "acme")
    write_storage(
        _DF, "duckdb", "hosts", config={"path": str(db_path)}, mode="truncate"
    )

    monkeypatch.setenv("TENANCY", "other")
    write_storage(
        _DF, "duckdb", "hosts", config={"path": str(db_path)}, mode="truncate"
    )

    monkeypatch.setenv("TENANCY", "acme")
    smaller = pd.DataFrame({"a": [9], "b": ["z"]})
    write_storage(
        smaller, "duckdb", "hosts", config={"path": str(db_path)}, mode="truncate"
    )

    conn = duckdb.connect(str(db_path))
    try:
        result = conn.execute("SELECT * FROM hosts").df()
    finally:
        conn.close()
    assert len(result) == 3  # 1 "acme" row (replaced) + 2 "other" rows (untouched)
    assert set(result["tenancy"]) == {"acme", "other"}


def test_duckdb_adds_new_column_to_existing_table(tmp_path: Path) -> None:
    db_path = tmp_path / "posture.duckdb"
    write_storage(
        _DF, "duckdb", "hosts", config={"path": str(db_path)}, mode="truncate"
    )
    wider = _DF.copy()
    wider["c"] = ["p", "q"]
    write_storage(
        wider, "duckdb", "hosts", config={"path": str(db_path)}, mode="truncate"
    )

    conn = duckdb.connect(str(db_path))
    try:
        result = conn.execute("SELECT * FROM hosts WHERE c IS NOT NULL").df()
    finally:
        conn.close()
    assert list(result["c"]) == ["p", "q"]


def test_duckdb_warns_on_missing_column(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    db_path = tmp_path / "posture.duckdb"
    write_storage(
        _DF, "duckdb", "hosts", config={"path": str(db_path)}, mode="truncate"
    )
    narrower = _DF[["a"]]
    with caplog.at_level("WARNING"):
        write_storage(
            narrower, "duckdb", "hosts", config={"path": str(db_path)}, mode="truncate"
        )
    assert any("'b'" in record.getMessage() for record in caplog.records)


def test_duckdb_write_page_truncate_first_page_only(tmp_path: Path) -> None:
    db_path = tmp_path / "posture.duckdb"
    store = DuckdbStorage({"path": str(db_path)})
    store.write_page(_DF, "hosts", mode="truncate")
    store.write_page(_DF, "hosts", mode="truncate")

    conn = duckdb.connect(str(db_path))
    try:
        result = conn.execute("SELECT * FROM hosts").df()
    finally:
        conn.close()
    assert len(result) == 4


def test_write_storage_unknown_backend(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Unknown storage"):
        write_storage(_DF, "bogus", "hosts", config={"path": str(tmp_path)})


def test_storage_factory_returns_matching_backend_instance(tmp_path: Path) -> None:
    store = Storage("csv", {"path": str(tmp_path)})
    assert isinstance(store, CsvStorage)
    store.write(_DF, "hosts")
    assert (tmp_path / "default" / "hosts.csv").exists()


def test_storage_factory_unknown_backend() -> None:
    with pytest.raises(ValueError, match="Unknown storage"):
        Storage("bogus", {})


def test_storage_factory_reused_across_write_page_calls(tmp_path: Path) -> None:
    store = Storage("sqlite", {"path": str(tmp_path / "posture.db")})
    store.write_page(_DF, "hosts", mode="truncate")
    store.write_page(_DF, "hosts", mode="truncate")
    conn = sqlite3.connect(tmp_path / "posture.db")
    try:
        result = pd.read_sql("SELECT * FROM hosts", conn)
    finally:
        conn.close()
    assert len(result) == 4


def test_postgres_dsn_passthrough_unchanged() -> None:
    store = PostgresStorage({"dsn": "postgresql://u:p@h:5432/d"})
    assert store._dsn == "postgresql://u:p@h:5432/d"


def test_postgres_discrete_keys_build_dsn() -> None:
    store = PostgresStorage({"host": "h", "dbname": "d", "user": "u", "password": "p"})
    assert store._dsn == "postgresql://u:p@h:5432/d"


def test_postgres_discrete_keys_use_custom_port() -> None:
    store = PostgresStorage(
        {"host": "h", "port": "6543", "dbname": "d", "user": "u", "password": "p"}
    )
    assert store._dsn == "postgresql://u:p@h:6543/d"


def test_postgres_discrete_keys_url_escape_special_characters() -> None:
    store = PostgresStorage(
        {"host": "h", "dbname": "d", "user": "u@x", "password": "p@ss word"}
    )
    assert store._dsn == "postgresql://u%40x:p%40ss%20word@h:5432/d"


def test_postgres_dsn_takes_precedence_over_discrete_keys() -> None:
    store = PostgresStorage(
        {
            "dsn": "postgresql://from-dsn/d",
            "host": "ignored",
            "dbname": "ignored",
            "user": "ignored",
            "password": "ignored",
        }
    )
    assert store._dsn == "postgresql://from-dsn/d"


def test_postgres_missing_config_raises() -> None:
    with pytest.raises(ValueError, match="Missing required config"):
        PostgresStorage({"host": "h"})


def test_storage_catalog_lists_every_backend() -> None:
    catalog = storage_catalog()
    assert set(catalog) == {
        "csv",
        "json",
        "parquet",
        "sqlite",
        "duckdb",
        "postgres",
        "gcs",
        "s3",
        "bigquery",
        "snowflake",
    }


def test_storage_catalog_reports_required_config() -> None:
    catalog = storage_catalog()
    assert catalog["csv"]["required_config"] == {"path": "POSTURE_CSV_PATH"}
    assert catalog["csv"]["optional_config"] == {}
    assert catalog["csv"]["class_name"] == "CsvStorage"


def test_storage_catalog_never_instantiates_a_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # No config/env vars set anywhere — a backend requiring config would
    # raise on __init__. storage_catalog() must never construct one.
    monkeypatch.delenv("POSTURE_POSTGRES_DSN", raising=False)
    storage_catalog()  # must not raise
