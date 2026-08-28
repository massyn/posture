from __future__ import annotations

from pathlib import Path
from types import TracebackType

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from posture.exceptions import StorageWriteError
from posture.storage.base import Storage, _check_mode


class ParquetStorage(Storage):
    env_prefix = "POSTURE_PARQUET"
    extension = "parquet"

    def _dump(self, df: pd.DataFrame, path: Path) -> None:
        df.to_parquet(path, index=False)

    def write_stream(self, name: str, *, mode: str = "truncate") -> _ParquetStream:
        """Open a single output file for ``name`` that pages are written
        into incrementally, as pyarrow row groups, rather than materialising
        the whole resource in memory or splitting it across one file per page
        (``write_page()``'s behaviour, unchanged for every other backend).

        Use it in place of ``write_page()`` when the resource is large enough
        that even per-page files are a lot of small files, and one file for
        the whole (paginated) resource is preferred::

            with parquet_store.write_stream("crowdstrike_hosts") as stream:
                for page in ccm.collect_page("hosts"):
                    stream.write(page)

        Same path layout as ``write()``'s non-paginated case (``mode``
        selects truncate-in-place vs. one dated snapshot file per day), and
        the same atomic-write guarantee: pages are written to a ``.tmp``
        sibling, which is only renamed into place if the ``with`` block exits
        without an exception. All pages must share the same columns/dtypes —
        pyarrow raises if a later page's schema doesn't match the first.
        Parquet-only: no other backend's format supports appending row
        groups to an already-open file, so this isn't part of the common
        ``Storage``/``StorageBackend`` interface.
        """
        _check_mode(mode, source=self.env_prefix.lower())
        path = self._path_for(name, mode=mode, paginated=False)
        return _ParquetStream(self, path)


class _ParquetStream:
    """Context manager returned by ``ParquetStorage.write_stream()``. Opens
    the underlying pyarrow ``ParquetWriter`` lazily, on the first page, since
    the file's schema is only known once a page's columns are seen."""

    def __init__(self, storage: ParquetStorage, path: Path) -> None:
        self._storage = storage
        self._path = path
        self._tmp_path = path.with_suffix(path.suffix + ".tmp")
        self._writer: pq.ParquetWriter | None = None

    def write(self, df: pd.DataFrame) -> None:
        """Append one page as a new row group."""
        df = self._storage._add_upload_timestamp(df)
        table = pa.Table.from_pandas(df, preserve_index=False)
        try:
            if self._writer is None:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                self._writer = pq.ParquetWriter(self._tmp_path, table.schema)
            self._writer.write_table(table)
        except Exception as exc:
            raise StorageWriteError(
                f"Failed to write page to '{self._path}': {exc}",
                source=self._storage.env_prefix.lower(),
            ) from exc

    def __enter__(self) -> _ParquetStream:  # noqa: PYI034
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._writer is not None:
            self._writer.close()
        if exc_type is not None or self._writer is None:
            return
        try:
            self._tmp_path.replace(self._path)
        except Exception as replace_exc:
            raise StorageWriteError(
                f"Failed to finalise '{self._path}': {replace_exc}",
                source=self._storage.env_prefix.lower(),
            ) from replace_exc
