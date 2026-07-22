import json
from pathlib import Path

import pandas as pd

from posture.collectors.phriendly_phishing import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "phriendly_phishing"

TRAININGS_MANIFEST = MANIFEST["trainings"]
CLICKS_MANIFEST = MANIFEST["clicks"]


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_trainings_page() -> None:
    df = parse(_load("trainings_page.json"), TRAININGS_MANIFEST, resource="trainings")

    assert len(df) == 2
    assert df.loc[0, "email"] == "alice@example.com"
    assert df.loc[0, "status"] == "completed"
    assert df.loc[0, "score"] == 92.5
    assert df["completed_date"].dtype == "datetime64[ns, UTC]"
    assert pd.isna(df.loc[1, "completed_date"])  # not yet completed
    assert pd.isna(df.loc[1, "score"])


def test_clicks_page() -> None:
    df = parse(_load("clicks_page.json"), CLICKS_MANIFEST, resource="clicks")

    assert len(df) == 2
    assert df.loc[0, "campaign_name"] == "Q1 Invoice Scam"
    assert df["clicked_date"].dtype == "datetime64[ns, UTC]"
    assert pd.isna(df.loc[0, "reported_date"])
    assert pd.isna(df.loc[1, "clicked_date"])  # reported instead of clicked
    assert df.loc[1, "reported_date"] is not pd.NaT
