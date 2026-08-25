import json
from pathlib import Path

import pandas as pd

from posture.collectors.endoflife import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "endoflife"

CYCLES_MANIFEST = MANIFEST["cycles"]


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_cycles_page() -> None:
    df = parse(_load("cycles_page.json"), CYCLES_MANIFEST, resource="cycles")

    assert len(df) == 2

    python_row = df.loc[0]
    assert python_row["product"] == "python"
    assert python_row["cycle"] == "3.13"
    assert bool(python_row["is_eoas"]) is True
    assert python_row["latest_version"] == "3.13.15"
    assert json.loads(python_row["custom"])["pep"] == "PEP-0719"
    assert df["release_date"].dtype == "datetime64[us, UTC]"
    assert df["eoas_from"].dtype == "datetime64[us, UTC]"

    # chrome doesn't carry EOAS/EOES at all (keys absent, not just null) and
    # has a null "latest" object — both must fall through to NaN/NaT, not a
    # parse failure, per the allowlist-over-a-superset-schema design.
    chrome_row = df.loc[1]
    assert chrome_row["product"] == "chrome"
    assert pd.isna(chrome_row["is_eoas"])
    assert pd.isna(chrome_row["eoas_from"])
    assert pd.isna(chrome_row["latest_version"])
    assert pd.isna(chrome_row["latest_date"])
    assert pd.isna(chrome_row["custom"])
