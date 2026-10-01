from __future__ import annotations

from pathlib import Path

import pandas as pd

from posture.storage.base import Schema, Storage


class CsvStorage(Storage):
    env_prefix = "POSTURE_CSV"
    extension = "csv"

    def _dump(self, df: pd.DataFrame, path: Path, schema: Schema | None) -> None:
        # CSV stores no column types, so there's nothing for `schema` to pin.
        df.to_csv(path, index=False)
