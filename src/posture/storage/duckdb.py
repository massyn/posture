"""DuckDB storage: one database file (config "path"), one table per name.

Every row carries a "tenancy" column (see TableStorage), so "truncate" means
tenancy-scoped: DELETE rows for the current tenancy, then insert the fresh
set, leaving other tenancies' rows in the same table untouched. "append" just
inserts.

Atomicity comes from DuckDB's own transactional DDL/DML, not a tmp-file/
rename.

Schema evolution: a column present in ``df`` but not yet in the table is
added (``ALTER TABLE ADD COLUMN``); a column present in the table but
missing from ``df`` is left untouched (never dropped) — just logged as a
warning, since it usually means an upstream field disappeared rather than
something this library should act on unasked.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, ClassVar

import duckdb
import pandas as pd

from posture.storage.base import TableStorage

logger = logging.getLogger("posture.storage.duckdb")

# Checked in order — the first matching pandas dtype predicate wins.
# Anything that doesn't match (strings, mixed-type "object" columns, etc.)
# falls through to VARCHAR.
_TYPE_MAP = (
    (pd.api.types.is_bool_dtype, "BOOLEAN"),
    (pd.api.types.is_integer_dtype, "BIGINT"),
    (pd.api.types.is_float_dtype, "DOUBLE"),
    (pd.api.types.is_datetime64_any_dtype, "TIMESTAMP"),
)


def _duckdb_type(series: pd.Series) -> str:
    for is_dtype, duckdb_type in _TYPE_MAP:
        if is_dtype(series.dtype):
            return duckdb_type
    return "VARCHAR"


def _quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


class DuckdbStorage(TableStorage):
    env_prefix = "POSTURE_DUCKDB"
    config_keys: ClassVar[dict[str, bool]] = {"path": True}

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._path = Path(self._config["path"])

    def __repr__(self) -> str:
        return f"DuckdbStorage(path={self._path!s})"

    def _write_table(self, df: pd.DataFrame, name: str, *, recreate: bool) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        df = self._add_tenancy_column(df)
        table = _quote_ident(name)
        conn = duckdb.connect(str(self._path))
        try:
            conn.register("_posture_df", df)
            try:
                # Explicit column/type list rather than "AS SELECT * FROM
                # _posture_df WHERE 1=0" — the latter lets DuckDB's own
                # pandas-scanner inference decide types from the (zero-row)
                # data instead of _duckdb_type(), and DuckDB infers an
                # all-null object column as INTEGER regardless of pandas
                # dtype. A later page with real string data in that column
                # (e.g. cve_db's cve_cpe.version_start_excluding, all-null
                # in an early year's file, real version strings in a later
                # one) then fails to insert with a cast error. _duckdb_type()
                # already falls back to VARCHAR for exactly this shape, so
                # creation must go through it too, not just _sync_columns'
                # later ALTER TABLE ADD COLUMN calls.
                column_defs = ", ".join(
                    f"{_quote_ident(col)} {_duckdb_type(df[col])}" for col in df.columns
                )
                conn.execute(f"CREATE TABLE IF NOT EXISTS {table} ({column_defs})")
                self._sync_columns(conn, name, df)
                if recreate:
                    conn.execute(
                        f"DELETE FROM {table} WHERE tenancy = ?", [self._tenancy]
                    )
                # Explicit column lists rather than bare "SELECT *"/"INSERT
                # INTO table" — schema evolution means the table's physical
                # column order (existing columns first, new ones appended by
                # _sync_columns) won't always match df's column order.
                columns = ", ".join(_quote_ident(col) for col in df.columns)
                conn.execute(
                    f"INSERT INTO {table} ({columns}) SELECT {columns} FROM _posture_df"
                )
            finally:
                conn.unregister("_posture_df")
        finally:
            conn.close()

    def _sync_columns(
        self, conn: duckdb.DuckDBPyConnection, name: str, df: pd.DataFrame
    ) -> None:
        existing = {
            row[0]
            for row in conn.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = ?",
                [name],
            ).fetchall()
        }
        new_cols = [col for col in df.columns if col not in existing]
        missing_cols = existing - set(df.columns)
        for col in new_cols:
            conn.execute(
                f"ALTER TABLE {_quote_ident(name)} ADD COLUMN "
                f"{_quote_ident(col)} {_duckdb_type(df[col])}"
            )
        if missing_cols:
            logger.warning(
                "duckdb table '%s' has column(s) %s not present in this write; "
                "leaving them untouched",
                name,
                sorted(missing_cols),
            )
