from __future__ import annotations

import io
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, ClassVar

import pandas as pd

from posture.exceptions import StorageConfigError, StorageWriteError
from posture.storage.base import Storage


class S3Storage(Storage):
    """AWS S3 backend — writes each table as a Parquet object.

    Same opinionated-layout rationale as GcsStorage — S3 has no notion of "a
    directory the developer points us at", so this backend owns the layout
    rather than taking a "path" prefix. The one difference from GcsStorage:
    "append" mode lays out Hive-style partitions (``YEAR=/MONTH=/DAY=``) so
    the output is directly queryable by Athena/Glue without a separate
    partition-projection config.

    - truncate, write():       <name>/<tenancy>.parquet
    - truncate, write_page():  <name>/<tenancy>/<uuid>.parquet
    - append,   write():       <name>/<tenancy>/YEAR=<yyyy>/MONTH=<mm>/DAY=<dd>/<name>.parquet
    - append,   write_page():  <name>/<tenancy>/YEAR=<yyyy>/MONTH=<mm>/DAY=<dd>/<uuid>.parquet

    ``tenancy`` comes from the ``TENANCY`` env var (default ``"default"``),
    matching the convention posture's collectors already use to separate
    multi-tenancy output.

    S3 object uploads are atomic per-object (a failed upload never partially
    replaces an existing object), so this needs no tmp-file-then-rename
    dance for "truncate" mode: _atomic_write is overridden to upload
    straight to the final object key instead of a local Path.
    """

    env_prefix = "POSTURE_S3"
    extension = "parquet"
    config_keys: ClassVar[dict[str, bool]] = {"bucket": True}

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config = self._resolve_config(config or {})
        self._tenancy = os.environ.get("TENANCY", "default")
        self._upload_timestamp = pd.Timestamp.now(tz=timezone.utc).tz_localize(None)
        self._truncated_dirs: set[str] = set()

        try:
            import boto3
        except ImportError as exc:
            raise StorageConfigError(
                "boto3 is required for the 's3' backend; "
                "install it with `pip install posture[s3]`",
                source=self.env_prefix.lower(),
            ) from exc

        self._bucket = self._config["bucket"]
        self._client = boto3.client("s3")

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(bucket={self._bucket!s})"

    @staticmethod
    def _partition_dir() -> Path:
        today = datetime.now(timezone.utc).date()
        return Path(f"YEAR={today:%Y}") / f"MONTH={today:%m}" / f"DAY={today:%d}"

    def _page_dir(self, name: str, *, mode: str) -> Path:
        root = Path(name) / self._tenancy
        return root / self._partition_dir() if mode == "append" else root

    def _path_for(self, name: str, *, mode: str, paginated: bool) -> Path:
        if not paginated:
            if mode == "append":
                return (
                    Path(name)
                    / self._tenancy
                    / self._partition_dir()
                    / f"{name}.parquet"
                )
            return Path(name) / f"{self._tenancy}.parquet"
        return self._page_dir(name, mode=mode) / f"{uuid.uuid4().hex}.parquet"

    def _dump(self, df: pd.DataFrame, path: Path) -> None:
        buffer = io.BytesIO()
        df.to_parquet(buffer, engine="pyarrow", index=False)
        buffer.seek(0)
        self._client.put_object(Bucket=self._bucket, Key=path.as_posix(), Body=buffer)

    def _atomic_write(self, df: pd.DataFrame, path: Path) -> None:
        try:
            self._dump(df, path)
        except Exception as exc:
            raise StorageWriteError(
                f"Failed to write object '{path.as_posix()}': {exc}",
                source=self.env_prefix.lower(),
            ) from exc
