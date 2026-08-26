"""SQLite storage: one database file (config "path"), one table per name.

Every row carries a "tenant" column (see TableStorage), so "truncate" means
tenant-scoped: DELETE rows for the current tenant, then insert the fresh
set, leaving other tenants' rows in the same table untouched. "append" just
inserts.

Atomicity comes from SQLite's own transactions rather than a tmp-file/
rename: a failed write() rolls back and leaves the previously-committed
table untouched.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, ClassVar

import pandas as pd

from posture.storage.base import TableStorage


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
        df = self._add_tenant_column(df)
        conn = sqlite3.connect(self._path)
        try:
            with conn:
                if recreate:
                    conn.execute(
                        f'DELETE FROM "{name}" WHERE tenant = ?', (self._tenant,)
                    )
                df.to_sql(name, conn, if_exists="append", index=False)
        except sqlite3.OperationalError:
            # DELETE against a table that doesn't exist yet — the insert
            # below creates it.
            with conn:
                df.to_sql(name, conn, if_exists="append", index=False)
        finally:
            conn.close()
