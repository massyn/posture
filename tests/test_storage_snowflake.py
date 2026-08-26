from __future__ import annotations

import pandas as pd
import pytest

from posture.exceptions import StorageConfigError
from posture.storage import SnowflakeStorage

_DF = pd.DataFrame({"a": [1, 2], "b": ["x", "y"]})

_BASE_CONFIG = {
    "account": "acct",
    "database": "DB",
    "schema": "SCHEMA",
    "authenticator": "SNOWFLAKE",
    "user": "svc",
    "password": "secret",
}


class _FakeCursor:
    def __init__(self, conn: _FakeConnection) -> None:
        self.conn = conn

    def execute(self, query: str, params=None) -> None:
        self.conn.executed.append((query, params))

    def close(self) -> None:
        pass


class _FakeConnection:
    def __init__(self) -> None:
        self.executed: list[tuple[str, object]] = []

    def cursor(self) -> _FakeCursor:
        return _FakeCursor(self)


@pytest.fixture
def fake_snowflake(monkeypatch: pytest.MonkeyPatch):
    conn = _FakeConnection()
    connect_calls: list[dict] = []

    def fake_connect(**kwargs):
        connect_calls.append(kwargs)
        return conn

    write_pandas_calls: list[dict] = []

    def fake_write_pandas(connection, df, table_name, **kwargs):
        write_pandas_calls.append({"df": df.copy(), "table_name": table_name, **kwargs})
        return True, None, len(df), None

    monkeypatch.setattr("snowflake.connector.connect", fake_connect)
    monkeypatch.setattr(
        "snowflake.connector.pandas_tools.write_pandas", fake_write_pandas
    )
    monkeypatch.delenv("TENANT", raising=False)
    return conn, connect_calls, write_pandas_calls


def test_snowflake_requires_authenticator_explicitly(fake_snowflake) -> None:
    config = dict(_BASE_CONFIG)
    del config["authenticator"]
    with pytest.raises(StorageConfigError, match="authenticator"):
        SnowflakeStorage(config)


def test_snowflake_connect_uses_only_resolved_config(fake_snowflake) -> None:
    _, connect_calls, _ = fake_snowflake
    SnowflakeStorage(_BASE_CONFIG)
    assert len(connect_calls) == 1
    kwargs = connect_calls[0]
    assert kwargs["account"] == "acct"
    assert kwargs["authenticator"] == "SNOWFLAKE"
    assert kwargs["database"] == "DB"
    assert kwargs["schema"] == "SCHEMA"
    assert kwargs["user"] == "svc"
    assert kwargs["password"] == "secret"
    assert "role" not in kwargs
    assert "warehouse" not in kwargs
    assert "workload_identity_provider" not in kwargs


def test_snowflake_workload_identity_auth_passthrough(fake_snowflake) -> None:
    _, connect_calls, _ = fake_snowflake
    config = {
        "account": "acct",
        "database": "DB",
        "schema": "SCHEMA",
        "authenticator": "WORKLOAD_IDENTITY",
        "workload_identity_provider": "GCP",
        "role": "SOME_ROLE",
        "warehouse": "SOME_WH",
    }
    SnowflakeStorage(config)
    kwargs = connect_calls[0]
    assert kwargs["authenticator"] == "WORKLOAD_IDENTITY"
    assert kwargs["workload_identity_provider"] == "GCP"
    assert kwargs["role"] == "SOME_ROLE"
    assert kwargs["warehouse"] == "SOME_WH"
    assert "user" not in kwargs
    assert "password" not in kwargs


def test_snowflake_truncate_creates_table_and_deletes_tenant_rows(
    fake_snowflake,
) -> None:
    conn, _, write_pandas_calls = fake_snowflake
    store = SnowflakeStorage(_BASE_CONFIG)
    store.write(_DF, "hosts", mode="truncate")

    create_stmts = [q for q, _ in conn.executed if q.startswith("CREATE TABLE")]
    delete_stmts = [(q, p) for q, p in conn.executed if q.startswith("DELETE")]
    assert len(create_stmts) == 1
    assert "DB.SCHEMA.HOSTS" in create_stmts[0]
    assert delete_stmts == [
        ("DELETE FROM DB.SCHEMA.HOSTS WHERE TENANT = %s", ("default",))
    ]

    assert len(write_pandas_calls) == 1
    call = write_pandas_calls[0]
    assert call["table_name"] == "HOSTS"
    assert (call["df"]["tenant"] == "default").all()


def test_snowflake_append_skips_delete(fake_snowflake) -> None:
    conn, _, write_pandas_calls = fake_snowflake
    store = SnowflakeStorage(_BASE_CONFIG)
    store.write(_DF, "hosts", mode="append")

    delete_stmts = [q for q, _ in conn.executed if q.startswith("DELETE")]
    assert delete_stmts == []
    assert len(write_pandas_calls) == 1


def test_snowflake_tenant_env_var_used(fake_snowflake, monkeypatch) -> None:
    conn, _, write_pandas_calls = fake_snowflake
    monkeypatch.setenv("TENANT", "acme")
    store = SnowflakeStorage(_BASE_CONFIG)
    store.write(_DF, "hosts", mode="truncate")

    delete_stmts = [(q, p) for q, p in conn.executed if q.startswith("DELETE")]
    assert delete_stmts == [
        ("DELETE FROM DB.SCHEMA.HOSTS WHERE TENANT = %s", ("acme",))
    ]
    assert (write_pandas_calls[0]["df"]["tenant"] == "acme").all()


def test_snowflake_empty_dataframe_skips_write_pandas(fake_snowflake) -> None:
    _, _, write_pandas_calls = fake_snowflake
    store = SnowflakeStorage(_BASE_CONFIG)
    store.write(pd.DataFrame({"a": [], "b": []}), "hosts", mode="truncate")
    assert write_pandas_calls == []
