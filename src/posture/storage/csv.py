from __future__ import annotations

from pathlib import Path

import pandas as pd

from posture.storage.base import Storage


class CsvStorage(Storage):
    env_prefix = "POSTURE_CSV"
    extension = "csv"

    def _dump(self, df: pd.DataFrame, path: Path) -> None:
        df.to_csv(path, index=False)
