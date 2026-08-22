"""Postgres storage: one database, one table per name, via psycopg3.

Connect either with discrete config keys (host/port/dbname/user/password —
the same convention every Collector uses for its own credentials) or, for
advanced connection options psycopg supports that discrete keys don't cover,
a single "dsn" that's used verbatim and takes precedence when given.

Atomicity comes from a single Postgres transaction, not a tmp-file/rename: a
failed write() rolls back and leaves the previously-committed table
untouched.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import pandas as pd
import psycopg
from psycopg import sql

from posture.exceptions import StorageConfigError
from posture.storage.base import TableStorage

_DEFAULT_PORT = "5432"
_REQUIRED_DISCRETE_KEYS = ("host", "dbname", "user", "password")

# Checked in order — the first matching pandas dtype predicate wins.
# Anything that doesn't match (strings, mixed-type "object" columns, etc.)
# falls through to TEXT.
_TYPE_MAP = (
    (pd.api.types.is_bool_dtype, "BOOLEAN"),
    (pd.api.types.is_integer_dtype, "BIGINT"),
    (pd.api.types.is_float_dtype, "DOUBLE PRECISION"),
    (pd.api.types.is_datetime64_any_dtype, "TIMESTAMPTZ"),
)


def _pg_type(series: pd.Series) -> str:
    for is_dtype, pg_type in _TYPE_MAP:
        if is_dtype(series.dtype):
            return pg_type
    return "TEXT"


class PostgresStorage(TableStorage):
    env_prefix = "POSTURE_POSTGRES"
    # None of these are individually required at the schema level — either
    # "dsn" alone or the full host/dbname/user/password set must be present,
    # which _resolve_config's per-key "required" flag can't express. __init__
    # checks that combination itself and raises its own ValueError.
    config_keys: dict[str, bool] = {
        "dsn": False,
        "host": False,
        "port": False,
        "dbname": False,
        "user": False,
        "password": False,
    }

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._dsn = self._build_dsn(self._config)

    @staticmethod
    def _build_dsn(resolved: dict[str, Any]) -> str:
        if "dsn" in resolved:
            return resolved["dsn"]
        missing = [key for key in _REQUIRED_DISCRETE_KEYS if key not in resolved]
        if missing:
            raise StorageConfigError(
                f"Missing required config: provide 'dsn', or all of "
                f"{list(_REQUIRED_DISCRETE_KEYS)} (missing {missing}) — "
                "explicitly or via env vars POSTURE_POSTGRES_HOST / "
                "_DBNAME / _USER / _PASSWORD",
                source="postgres",
            )
        port = resolved.get("port", _DEFAULT_PORT)
        user = quote(resolved["user"], safe="")
        password = quote(resolved["password"], safe="")
        return f"postgresql://{user}:{password}@{resolved['host']}:{port}/{resolved['dbname']}"

    def __repr__(self) -> str:
        return "PostgresStorage(dsn=<redacted>)"

    def _write_table(self, df: pd.DataFrame, name: str, *, recreate: bool) -> None:
        table = sql.Identifier(name)
        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                if recreate:
                    cur.execute(sql.SQL("DROP TABLE IF EXISTS {}").format(table))
                column_defs = sql.SQL(", ").join(
                    sql.SQL("{} {}").format(
                        sql.Identifier(col), sql.SQL(_pg_type(df[col]))
                    )
                    for col in df.columns
                )
                cur.execute(
                    sql.SQL("CREATE TABLE IF NOT EXISTS {} ({})").format(
                        table, column_defs
                    )
                )
                if df.empty:
                    return
                columns = sql.SQL(", ").join(sql.Identifier(col) for col in df.columns)
                copy_sql = sql.SQL("COPY {} ({}) FROM STDIN").format(table, columns)
                with cur.copy(copy_sql) as copy:
                    for row in df.itertuples(index=False, name=None):
                        copy.write_row(tuple(None if pd.isna(v) else v for v in row))
