import json
from pathlib import Path

import pandas as pd

from posture.collectors.workspaceone import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "workspaceone"

COMPUTERS_MANIFEST = MANIFEST["computers"]


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_computers_page() -> None:
    df = parse(_load("computers_page.json"), COMPUTERS_MANIFEST, resource="computers")

    assert len(df) == 2
    assert "ip_address" not in df.columns  # computed fallback, deliberately dropped
    assert df.loc[0, "device_id"] == "101"  # Id.Value, coerced to str
    assert df.loc[0, "uuid"] == "uuid-101"
    assert bool(df.loc[0, "is_supervised"]) is True
    assert bool(df.loc[1, "is_supervised"]) is False
    assert df["last_seen"].dtype == "datetime64[ns, UTC]"
    assert pd.isna(df.loc[1, "last_seen"])  # absent in fixture
