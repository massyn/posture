"""SQLite storage: one database file (config "path"), one table per name.

Atomicity comes from SQLite's own transactions rather than a tmp-file/
rename: a failed write() rolls back and leaves the previously-committed
table untouched.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pandas as pd

from posture.storage.base import TableStorage


class SqliteStorage(TableStorage):
    env_prefix = "POSTURE_SQLITE"
    config_keys: dict[str, bool] = {"path": True}

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._path = Path(self._config["path"])

    def __repr__(self) -> str:
        return f"SqliteStorage(path={self._path!s})"

    def _write_table(self, df: pd.DataFrame, name: str, *, recreate: bool) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self._path)
        try:
            with conn:
                df.to_sql(
                    name,
                    conn,
                    if_exists="replace" if recreate else "append",
                    index=False,
                )
        finally:
            conn.close()
