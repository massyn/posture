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


class GcsStorage(Storage):
    """Google Cloud Storage backend — writes each table as a Parquet blob.

    Unlike the local file-backed backends, GCS has no notion of "a directory
    the developer points us at" to layer path/mode logic onto — so this
    backend owns an opinionated layout instead of taking a "path" prefix:

    - truncate, write():       <name>/<tenancy>.parquet
    - truncate, write_page():  <name>/<tenancy>/<uuid>.parquet
    - append,   write():       <name>/<tenancy>/<YYYY-MM-DD>.parquet
    - append,   write_page():  <name>/<tenancy>/<YYYY-MM-DD>/<uuid>.parquet

    ``tenancy`` comes from the ``TENANCY`` env var (default ``"default"``),
    matching the convention posture's collectors already use to separate
    multi-tenancy output.

    GCS object uploads are atomic per-blob (a failed upload never partially
    replaces an existing object), so this needs no tmp-file-then-rename
    dance for "truncate" mode: _atomic_write is overridden to upload
    straight to the final blob path instead of a local Path.
    """

    env_prefix = "POSTURE_GCS"
    extension = "parquet"
    config_keys: ClassVar[dict[str, bool]] = {"bucket": True}

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config = self._resolve_config(config or {})
        self._tenancy = os.environ.get("TENANCY", "default")
        self._upload_timestamp = pd.Timestamp.now(tz=timezone.utc).tz_localize(None)
        self._truncated_dirs: set[str] = set()

        try:
            from google.cloud import storage
        except ImportError as exc:
            raise StorageConfigError(
                "google-cloud-storage is required for the 'gcs' backend; "
                "install it with `pip install posture[gcs]`",
                source=self.env_prefix.lower(),
            ) from exc

        self._client = storage.Client()
        self._bucket = self._client.bucket(self._config["bucket"])

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(bucket={self._config['bucket']!s})"

    @staticmethod
    def _today() -> str:
        return f"{datetime.now(timezone.utc).date():%Y-%m-%d}"

    def _page_dir(self, name: str, *, mode: str) -> Path:
        root = Path(name) / self._tenancy
        return root / self._today() if mode == "append" else root

    def _path_for(self, name: str, *, mode: str, paginated: bool) -> Path:
        if not paginated:
            if mode == "append":
                return Path(name) / self._tenancy / f"{self._today()}.parquet"
            return Path(name) / f"{self._tenancy}.parquet"
        return self._page_dir(name, mode=mode) / f"{uuid.uuid4().hex}.parquet"

    def _dump(self, df: pd.DataFrame, path: Path) -> None:
        buffer = io.BytesIO()
        df.to_parquet(buffer, engine="pyarrow", index=False)
        buffer.seek(0)
        blob = self._bucket.blob(path.as_posix())
        blob.upload_from_file(buffer, content_type="application/octet-stream")

    def _atomic_write(self, df: pd.DataFrame, path: Path) -> None:
        try:
            self._dump(df, path)
        except Exception as exc:
            raise StorageWriteError(
                f"Failed to write blob '{path.as_posix()}': {exc}",
                source=self.env_prefix.lower(),
            ) from exc
