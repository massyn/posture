from __future__ import annotations

from pathlib import Path

import pandas as pd

from posture.storage.base import Schema, Storage


class JsonStorage(Storage):
    env_prefix = "POSTURE_JSON"
    extension = "json"

    def _dump(self, df: pd.DataFrame, path: Path, schema: Schema | None) -> None:
        # JSON stores no column types, so there's nothing for `schema` to pin.
        df.to_json(path, orient="records", date_format="iso")
