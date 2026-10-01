from __future__ import annotations

from pathlib import Path
from types import TracebackType
from typing import BinaryIO

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from posture.exceptions import StorageWriteError
from posture.storage.base import Schema, Storage, _check_mode

_ARROW_TYPES = {
    "str": pa.string(),
    "json": pa.string(),
    "int": pa.int64(),
    "float": pa.float64(),
    "bool": pa.bool_(),
    "datetime": pa.timestamp("us", tz="UTC"),
}


def arrow_schema(df: pd.DataFrame, schema: Schema | None) -> pa.Schema:
    """pyarrow schema for ``df``: each column ``schema`` names gets its
    declared type; every other column (``upload_timestamp``, extras on a
    hand-built frame, or all of them when ``schema`` is None) keeps the type
    inferred from ``df``'s dtypes. Same fall-through rules as
    ``resolve_sql_type`` — an unrecognised declared type name is inferred too.

    Fixing a multi-page file's schema up front this way is what stops a
    column that's all-null on the first page being typed ``null`` and then
    rejecting every later page with a value in it (locked decision #11).
    """
    inferred = pa.Schema.from_pandas(df, preserve_index=False)
    if schema is None:
        return inferred
    fields = [
        (
            pa.field(field.name, _ARROW_TYPES[schema[field.name]])
            if schema.get(field.name) in _ARROW_TYPES
            else field
        )
        for field in inferred
    ]
    return pa.schema(fields, metadata=inferred.metadata)


def write_parquet(
    df: pd.DataFrame, target: Path | BinaryIO, schema: Schema | None
) -> None:
    """Write ``df`` as one parquet file to a path or binary buffer, with
    column types from ``arrow_schema`` — shared by every backend that writes
    parquet files (parquet/s3/gcs), so a declared column is typed the same in
    every file of a multi-file dataset rather than per file's own dtypes."""
    table = pa.Table.from_pandas(
        df, schema=arrow_schema(df, schema), preserve_index=False
    )
    pq.write_table(table, target)


class ParquetStorage(Storage):
    env_prefix = "POSTURE_PARQUET"
    extension = "parquet"

    def _dump(self, df: pd.DataFrame, path: Path, schema: Schema | None) -> None:
        write_parquet(df, path, schema)

    def write_stream(
        self, name: str, *, mode: str = "truncate", schema: Schema | None = None
    ) -> _ParquetStream:
        """Open a single output file for ``name`` that pages are written
        into incrementally, as pyarrow row groups, rather than materialising
        the whole resource in memory or splitting it across one file per page
        (``write_page()``'s behaviour, unchanged for every other backend).

        Use it in place of ``write_page()`` when the resource is large enough
        that even per-page files are a lot of small files, and one file for
        the whole (paginated) resource is preferred::

            with parquet_store.write_stream(
                "crowdstrike_hosts", schema=ccm.column_types("hosts")
            ) as stream:
                for page in ccm.collect_page("hosts"):
                    stream.write(page)

        Same path layout as ``write()``'s non-paginated case (``mode``
        selects truncate-in-place vs. one dated snapshot file per day), and
        the same atomic-write guarantee: pages are written to a ``.tmp``
        sibling, which is only renamed into place if the ``with`` block exits
        without an exception.

        The file's schema is fixed on the first page (see ``arrow_schema``)
        and every later page is converted to it. Pass ``schema`` (from
        ``Collector.column_types``) so declared columns get their manifest
        type rather than the first page's dtype — without it, a column that
        is all-null on the first page is typed ``null`` and the first later
        page with a value in that column raises StorageWriteError.
        Parquet-only: no other backend's format supports appending row
        groups to an already-open file, so this isn't part of the common
        ``Storage``/``StorageBackend`` interface.
        """
        _check_mode(mode, source=self.env_prefix.lower())
        path = self._path_for(name, mode=mode, paginated=False)
        return _ParquetStream(self, path, schema)


class _ParquetStream:
    """Context manager returned by ``ParquetStorage.write_stream()``. Opens
    the underlying pyarrow ``ParquetWriter`` lazily, on the first page, since
    the file's schema is only known once a page's columns are seen."""

    def __init__(
        self, storage: ParquetStorage, path: Path, schema: Schema | None
    ) -> None:
        self._storage = storage
        self._path = path
        self._tmp_path = path.with_suffix(path.suffix + ".tmp")
        self._schema = schema
        self._writer: pq.ParquetWriter | None = None

    def write(self, df: pd.DataFrame) -> None:
        """Append one page as a new row group."""
        df = self._storage._add_upload_timestamp(df)
        try:
            if self._writer is None:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                self._writer = pq.ParquetWriter(
                    self._tmp_path, arrow_schema(df, self._schema)
                )
            table = pa.Table.from_pandas(
                df, schema=self._writer.schema, preserve_index=False
            )
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
