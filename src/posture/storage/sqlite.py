"""SQLite storage: one database file (config "path"), one table per name.

Every row carries a "tenancy" column (see TableStorage), so "truncate" means
tenancy-scoped: DELETE rows for the current tenancy, then insert the fresh
set, leaving other tenancies' rows in the same table untouched. "append" just
inserts.

Atomicity comes from SQLite's own transactions rather than a tmp-file/
rename: a failed write() rolls back and leaves the previously-committed
table untouched.

Schema evolution: a column present in ``df`` but not yet in the table is
added (``ALTER TABLE ADD COLUMN``); a column present in the table but
missing from ``df`` is left untouched (never dropped) — just logged as a
warning, since it usually means an upstream field disappeared rather than
something this library should act on unasked.
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import Any, ClassVar

import pandas as pd

from posture.storage.base import TableStorage

logger = logging.getLogger("posture.storage.sqlite")

# Checked in order — the first matching pandas dtype predicate wins.
# Anything that doesn't match (strings, mixed-type "object" columns, etc.)
# falls through to TEXT.
_TYPE_MAP = (
    (pd.api.types.is_bool_dtype, "BOOLEAN"),
    (pd.api.types.is_integer_dtype, "INTEGER"),
    (pd.api.types.is_float_dtype, "REAL"),
    (pd.api.types.is_datetime64_any_dtype, "TIMESTAMP"),
)


def _sqlite_type(series: pd.Series) -> str:
    for is_dtype, sqlite_type in _TYPE_MAP:
        if is_dtype(series.dtype):
            return sqlite_type
    return "TEXT"


class SqliteStorage(TableStorage):
    env_prefix = "POSTURE_SQLITE"
    config_keys: ClassVar[dict[str, bool]] = {"path": True}

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._path = Path(self._config["path"])

    def __repr__(self) -> str:
        return f"SqliteStorage(path={self._path!s})"

    def _write_table(self, df: pd.DataFrame, name: str, *, recreate: bool) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        df = self._add_tenancy_column(df)
        conn = sqlite3.connect(self._path)
        try:
            with conn:
                table_exists = self._sync_columns(conn, name, df)
                if recreate and table_exists:
                    conn.execute(
                        f'DELETE FROM "{name}" WHERE tenancy = ?', (self._tenancy,)
                    )
                # If the table doesn't exist yet, to_sql() creates it from
                # exactly df's columns — no separate CREATE TABLE needed.
                df.to_sql(name, conn, if_exists="append", index=False)
        finally:
            conn.close()

    def _sync_columns(
        self, conn: sqlite3.Connection, name: str, df: pd.DataFrame
    ) -> bool:
        """Add any of df's columns missing from an existing table; warn (never
        drop) about any of the table's columns missing from df. Returns
        whether the table already existed."""
        existing = {
            row[1] for row in conn.execute(f'PRAGMA table_info("{name}")').fetchall()
        }
        if not existing:
            return False
        new_cols = [col for col in df.columns if col not in existing]
        missing_cols = existing - set(df.columns)
        for col in new_cols:
            conn.execute(
                f'ALTER TABLE "{name}" ADD COLUMN "{col}" {_sqlite_type(df[col])}'
            )
        if missing_cols:
            logger.warning(
                "sqlite table '%s' has column(s) %s not present in this write; "
                "leaving them untouched",
                name,
                sorted(missing_cols),
            )
        return True
