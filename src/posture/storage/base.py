"""Storage ABC: config resolution, path layout, and atomic file writes shared
by every local file-backed storage backend (csv/json/parquet).

One Storage instance = one target location (a base directory, or — for
sqlite — one database file), matching Collector's "one instance = one
tenant" convention.

Two write methods, mirroring Collector.collect()/collect_page():

- ``write(df, name, mode=...)`` — one-shot: the whole DataFrame becomes a
  single file (or, in "append" mode, a dated snapshot file).
- ``write_page(df, name, mode=...)`` — call once per page when the caller is
  already iterating pages (e.g. off Collector.collect_page()) rather than
  holding a whole resource in memory. Each call writes its own
  uniquely-named file under a per-``name`` directory.

Path layout, driven entirely by ``mode``:

- truncate, write():       <path>/<name>.<ext>                       (overwritten every run)
- truncate, write_page():  <path>/<name>/<uuid>.<ext>                 (directory cleared on the run's first page)
- append,   write():       <path>/<YYYY>/<MM>/<DD>/<name>.<ext>       (one snapshot per day)
- append,   write_page():  <path>/<YYYY>/<MM>/<DD>/<name>/<uuid>.<ext> (history is never cleared)

Errors: a missing/invalid config value or `mode` raises StorageConfigError
(also a ValueError, for backward compatibility); anything that goes wrong
during the actual write — a driver/library exception from pandas, sqlite3,
duckdb, or psycopg — is wrapped as StorageWriteError with the original
exception attached as __cause__. Both are PostureError subclasses, so
`except PostureError` catches every storage failure the same way it catches
every collector failure.
"""

from __future__ import annotations

import os
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, ClassVar, Protocol, runtime_checkable

import pandas as pd

from posture.exceptions import StorageConfigError, StorageError, StorageWriteError

_MODES = ("truncate", "append")


@runtime_checkable
class StorageBackend(Protocol):
    """The contract every storage backend (file-based or table-based) must
    satisfy — the actual type behind the "csv"/"json"/.../"postgres" keys in
    posture.storage's registry. Both Storage and TableStorage implement it
    structurally; a class satisfies it by having matching methods, no
    explicit subclassing required (that's what makes it a Protocol rather
    than another ABC to inherit from)."""

    def __init__(self, config: dict[str, Any] | None = None) -> None: ...

    def write(self, df: pd.DataFrame, name: str, *, mode: str = ...) -> None: ...

    def write_page(self, df: pd.DataFrame, name: str, *, mode: str = ...) -> None: ...


def _check_mode(mode: str, *, source: str) -> None:
    if mode not in _MODES:
        raise StorageConfigError(
            f"Invalid mode '{mode}': must be one of {_MODES}", source=source
        )


class _ConfigResolverMixin:
    """Explicit-kwarg-then-env-var config resolution, same rules as
    Collector._resolve_config (posture/base.py) — duplicated rather than
    shared across the two class hierarchies since Collector's version is
    entangled with URL normalisation that storage backends don't need."""

    #: Env var prefix used for config resolution, e.g. "POSTURE_CSV".
    env_prefix: str = ""

    #: key -> required. A required key missing everywhere raises
    #: StorageConfigError (also a ValueError).
    config_keys: ClassVar[dict[str, bool]] = {}

    def _resolve_config(self, explicit: dict[str, Any]) -> dict[str, Any]:
        resolved: dict[str, Any] = {}
        for key, required in self.config_keys.items():
            if key in explicit:
                resolved[key] = explicit[key]
                continue
            env_var = f"{self.env_prefix}_{key.upper()}"
            value = os.environ.get(env_var)
            if value is None:
                if required:
                    raise StorageConfigError(
                        f"Missing required config '{key}': set it explicitly or "
                        f"via env var {env_var}",
                        source=self.env_prefix.lower(),
                    )
                continue
            resolved[key] = value
        return resolved


class Storage(_ConfigResolverMixin, ABC):
    """Base class for a single local file-backed storage target."""

    config_keys: ClassVar[dict[str, bool]] = {"path": True}

    #: File extension written for this format, e.g. "csv".
    extension: str = ""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config = self._resolve_config(config or {})
        self._base_dir = Path(self._config["path"])
        # Tracks which (name) directories have already been cleared for a
        # truncating paginated write this run, so only the first page of a
        # given name wipes prior contents — later pages just add to it.
        self._truncated_dirs: set[str] = set()

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(path={self._base_dir!s})"

    def write(self, df: pd.DataFrame, name: str, *, mode: str = "truncate") -> None:
        """Write the whole of ``df`` as a single file."""
        _check_mode(mode, source=self.env_prefix.lower())
        path = self._path_for(name, mode=mode, paginated=False)
        self._atomic_write(df, path)

    def write_page(
        self, df: pd.DataFrame, name: str, *, mode: str = "truncate"
    ) -> None:
        """Write one page of ``name`` as its own uniquely-named file.

        Call once per page from a loop over Collector.collect_page() rather
        than materialising the whole resource first. On a truncating run,
        the first page for a given ``name`` clears out any files left by a
        previous run before writing; append mode never clears anything.
        """
        _check_mode(mode, source=self.env_prefix.lower())
        if mode == "truncate" and name not in self._truncated_dirs:
            self._clear_dir(self._page_dir(name, mode=mode))
            self._truncated_dirs.add(name)
        path = self._path_for(name, mode=mode, paginated=True)
        self._atomic_write(df, path)

    def _dated_dir(self) -> Path:
        today = datetime.now(timezone.utc).date()
        return self._base_dir / f"{today:%Y}" / f"{today:%m}" / f"{today:%d}"

    def _page_dir(self, name: str, *, mode: str) -> Path:
        root = self._dated_dir() if mode == "append" else self._base_dir
        return root / name

    def _path_for(self, name: str, *, mode: str, paginated: bool) -> Path:
        if not paginated:
            root = self._dated_dir() if mode == "append" else self._base_dir
            return root / f"{name}.{self.extension}"
        return self._page_dir(name, mode=mode) / f"{uuid.uuid4().hex}.{self.extension}"

    @staticmethod
    def _clear_dir(path: Path) -> None:
        if not path.is_dir():
            return
        for child in path.iterdir():
            if child.is_file():
                child.unlink()

    def _atomic_write(self, df: pd.DataFrame, path: Path) -> None:
        """Write to a ``.tmp`` sibling first, then rename into place — a
        failure partway through ``_dump`` never leaves a broken/truncated
        file at ``path``, only an orphaned ``.tmp``. Any failure here — from
        pandas/pyarrow or the filesystem — becomes StorageWriteError with
        the original exception as __cause__."""
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = path.with_suffix(path.suffix + ".tmp")
            self._dump(df, tmp_path)
            tmp_path.replace(path)
        except StorageError:
            raise
        except Exception as exc:
            raise StorageWriteError(
                f"Failed to write '{path}': {exc}", source=self.env_prefix.lower()
            ) from exc

    @abstractmethod
    def _dump(self, df: pd.DataFrame, path: Path) -> None:
        """Write ``df`` to ``path`` in this backend's format."""


class TableStorage(_ConfigResolverMixin, ABC):
    """Base class shared by one-database/one-table-per-name backends
    (sqlite/duckdb/postgres). A table isn't a file, so these don't use
    Storage's directory/pagination path layout — but they share the exact
    same truncate-on-first-page tracking Storage.write_page() uses.
    Subclasses implement only ``_write_table(df, name, recreate=...)`` for
    their own DDL/DML; write()/write_page()/mode validation live here once.
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config = self._resolve_config(config or {})
        # Tracks which tables this run has already recreated, so only the
        # first page of a truncating write_page() clears prior rows.
        self._truncated_tables: set[str] = set()

    def write(self, df: pd.DataFrame, name: str, *, mode: str = "truncate") -> None:
        _check_mode(mode, source=self.env_prefix.lower())
        self._call_write_table(df, name, recreate=mode == "truncate")

    def write_page(
        self, df: pd.DataFrame, name: str, *, mode: str = "truncate"
    ) -> None:
        _check_mode(mode, source=self.env_prefix.lower())
        if mode == "truncate" and name not in self._truncated_tables:
            self._call_write_table(df, name, recreate=True)
            self._truncated_tables.add(name)
            return
        self._call_write_table(df, name, recreate=False)

    def _call_write_table(self, df: pd.DataFrame, name: str, *, recreate: bool) -> None:
        """Wraps _write_table() so any driver exception (psycopg, sqlite3,
        duckdb, ...) becomes StorageWriteError with the original as
        __cause__, instead of a different raw exception type per backend."""
        try:
            self._write_table(df, name, recreate=recreate)
        except StorageError:
            raise
        except Exception as exc:
            raise StorageWriteError(
                f"Failed to write table '{name}': {exc}",
                source=self.env_prefix.lower(),
            ) from exc

    @abstractmethod
    def _write_table(self, df: pd.DataFrame, name: str, *, recreate: bool) -> None:
        """Write ``df`` into table ``name``, recreating it first if ``recreate``."""
