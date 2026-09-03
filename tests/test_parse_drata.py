import json
from pathlib import Path

import pandas as pd

from posture.collectors.drata import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "drata"


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_controls_page() -> None:
    df = parse(_load("controls_page.json"), MANIFEST["controls"], resource="controls")

    assert len(df) == 2
    assert df.loc[0, "code"] == "DCC-1"
    assert bool(df.loc[0, "is_ready"]) is True
    assert bool(df.loc[1, "is_ready"]) is False
    assert df["created_at"].dtype == "datetime64[us, UTC]"
    assert pd.isna(df.loc[0, "archived_at"])
    assert not pd.isna(df.loc[1, "archived_at"])


def test_devices_page() -> None:
    df = parse(_load("devices_page.json"), MANIFEST["devices"], resource="devices")

    assert len(df) == 1
    assert df.loc[0, "compliance_status"] == "COMPLIANT"
    assert df.loc[0, "personnel_email"] == "jsmith@example.com"
    assert bool(df.loc[0, "is_encrypted"]) is True
    assert df["last_checked_at"].dtype == "datetime64[us, UTC]"
