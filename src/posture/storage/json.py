from __future__ import annotations

from pathlib import Path

import pandas as pd

from posture.storage.base import Storage


class JsonStorage(Storage):
    env_prefix = "POSTURE_JSON"
    extension = "json"

    def _dump(self, df: pd.DataFrame, path: Path) -> None:
        df.to_json(path, orient="records", date_format="iso")
