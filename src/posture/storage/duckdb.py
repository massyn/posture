"""DuckDB storage: one database file (config "path"), one table per name.

Every row carries a "tenant" column (see TableStorage), so "truncate" means
tenant-scoped: DELETE rows for the current tenant, then insert the fresh
set, leaving other tenants' rows in the same table untouched. "append" just
inserts.

Atomicity comes from DuckDB's own transactional DDL/DML, not a tmp-file/
rename.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

import duckdb
import pandas as pd

from posture.storage.base import TableStorage


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
        df = self._add_tenant_column(df)
        table = _quote_ident(name)
        conn = duckdb.connect(str(self._path))
        try:
            conn.register("_posture_df", df)
            try:
                conn.execute(
                    f"CREATE TABLE IF NOT EXISTS {table} AS "
                    "SELECT * FROM _posture_df WHERE 1=0"
                )
                if recreate:
                    conn.execute(
                        f"DELETE FROM {table} WHERE tenant = ?", [self._tenant]
                    )
                conn.execute(f"INSERT INTO {table} SELECT * FROM _posture_df")
            finally:
                conn.unregister("_posture_df")
        finally:
            conn.close()
