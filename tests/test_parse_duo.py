import json
from pathlib import Path

import pandas as pd

from posture.collectors.duo import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "duo"


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_users_page() -> None:
    df = parse(_load("users_page.json"), MANIFEST["users"], resource="users")

    assert len(df) == 2
    assert df.loc[0, "username"] == "jsmith"
    assert bool(df.loc[0, "is_enrolled"]) is True
    assert bool(df.loc[1, "is_enrolled"]) is False
    # epoch seconds -> tz-aware UTC datetime
    assert df["created"].dtype == "datetime64[us, UTC]"
    assert df.loc[0, "created"] == pd.Timestamp("2017-03-15 21:18:49", tz="UTC")
    assert pd.isna(df.loc[1, "last_login"])
    # list of objects -> JSON string in the cell
    assert isinstance(df.loc[0, "groups"], str)
    assert "Engineering" in df.loc[0, "groups"]


def test_endpoints_page() -> None:
    df = parse(
        _load("endpoints_page.json"), MANIFEST["endpoints"], resource="endpoints"
    )

    assert len(df) == 1
    assert df.loc[0, "disk_encryption_status"] == "On"
    assert df.loc[0, "os_version"] == "14.1.2"
    assert df["last_updated"].dtype == "datetime64[us, UTC]"
