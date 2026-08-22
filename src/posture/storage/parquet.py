from __future__ import annotations

from pathlib import Path

import pandas as pd

from posture.storage.base import Storage


class ParquetStorage(Storage):
    env_prefix = "POSTURE_PARQUET"
    extension = "parquet"

    def _dump(self, df: pd.DataFrame, path: Path) -> None:
        df.to_parquet(path, index=False)
