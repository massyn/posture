"""Postgres storage: one database, one table per name, via psycopg3.

Connect either with discrete config keys (host/port/dbname/user/password —
the same convention every Collector uses for its own credentials) or, for
advanced connection options psycopg supports that discrete keys don't cover,
a single "dsn" that's used verbatim and takes precedence when given.

Every row carries a "tenancy" column (see TableStorage), so "truncate" means
tenancy-scoped: DELETE rows for the current tenancy, then insert the fresh
set, leaving other tenancies' rows in the same table untouched. "append" just
inserts.

Atomicity comes from a single Postgres transaction, not a tmp-file/rename: a
failed write() rolls back and leaves the previously-committed table
untouched.

Schema evolution: a column present in ``df`` but not yet in the table is
added (``ALTER TABLE ADD COLUMN``); a column present in the table but
missing from ``df`` is left untouched (never dropped) — just logged as a
warning, since it usually means an upstream field disappeared rather than
something this library should act on unasked.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar
from urllib.parse import quote

import pandas as pd
import psycopg
from psycopg import sql

from posture.exceptions import StorageConfigError
from posture.storage.base import TableStorage

logger = logging.getLogger("posture.storage.postgres")

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
    config_keys: ClassVar[dict[str, bool]] = {
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
        df = self._add_tenancy_column(df)
        table = sql.Identifier(name)
        with psycopg.connect(self._dsn) as conn, conn.cursor() as cur:
            column_defs = sql.SQL(", ").join(
                sql.SQL("{} {}").format(sql.Identifier(col), sql.SQL(_pg_type(df[col])))
                for col in df.columns
            )
            cur.execute(
                sql.SQL("CREATE TABLE IF NOT EXISTS {} ({})").format(table, column_defs)
            )
            self._sync_columns(cur, name, df)
            if recreate:
                cur.execute(
                    sql.SQL("DELETE FROM {} WHERE tenancy = %s").format(table),
                    (self._tenancy,),
                )
            if df.empty:
                return
            columns = sql.SQL(", ").join(sql.Identifier(col) for col in df.columns)
            copy_sql = sql.SQL("COPY {} ({}) FROM STDIN").format(table, columns)
            with cur.copy(copy_sql) as copy:
                for row in df.itertuples(index=False, name=None):
                    copy.write_row(tuple(None if pd.isna(v) else v for v in row))

    def _sync_columns(self, cur: psycopg.Cursor, name: str, df: pd.DataFrame) -> None:
        cur.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name = %s",
            (name,),
        )
        existing = {row[0] for row in cur.fetchall()}
        new_cols = [col for col in df.columns if col not in existing]
        missing_cols = existing - set(df.columns)
        for col in new_cols:
            cur.execute(
                sql.SQL("ALTER TABLE {} ADD COLUMN {} {}").format(
                    sql.Identifier(name),
                    sql.Identifier(col),
                    sql.SQL(_pg_type(df[col])),
                )
            )
        if missing_cols:
            logger.warning(
                "postgres table '%s' has column(s) %s not present in this write; "
                "leaving them untouched",
                name,
                sorted(missing_cols),
            )
