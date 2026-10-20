import json
from pathlib import Path

import pandas as pd

from posture.collectors.proofpoint_sat import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "proofpoint_sat"


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_phishing_page() -> None:
    df = parse(_load("phishing_page.json"), MANIFEST["phishing"], resource="phishing")

    assert len(df) == 2
    assert df.loc[0, "id"] == "a1b2c3"
    assert df.loc[0, "user_email_address"] == "alice@example.com"
    assert df.loc[0, "event_type"] == "Email Click"
    assert json.loads(df.loc[0, "user_tags"]) == {"Department": "Finance"}
    assert df["event_timestamp"].dtype == "datetime64[us, UTC]"
    assert df["campaign_start_date"].dtype == "datetime64[us, UTC]"
    assert not df.loc[1, "user_active"]
    assert pd.isna(df.loc[1, "event_timestamp"])  # null in fixture
    assert pd.isna(df.loc[1, "user_tags"])  # absent in fixture


def test_training_page_coerces_string_numerics() -> None:
    df = parse(_load("training_page.json"), MANIFEST["training"], resource="training")

    assert len(df) == 1
    assert df.loc[0, "seconds_in_module_attempt"] == 684
    assert df.loc[0, "module_attempt_score"] == 90.5
    assert df.loc[0, "module_attempt_score_correct"] == 9
    assert df["assignment_due_date"].dtype == "datetime64[us, UTC]"
    assert pd.isna(df.loc[0, "force_completed_date"])  # absent in fixture


def test_phishalarm_page() -> None:
    df = parse(
        _load("phishalarm_page.json"), MANIFEST["phishalarm"], resource="phishalarm"
    )

    assert len(df) == 1
    assert df.loc[0, "action"] == "Reported"
    assert df.loc[0, "elapsed_hours"] == 1.5
    assert df["reported_date"].dtype == "datetime64[us, UTC]"


def test_empty_page_returns_declared_columns() -> None:
    df = parse([], MANIFEST["cyberstrength"], resource="cyberstrength")

    assert len(df) == 0
    assert set(MANIFEST["cyberstrength"]["columns"]) <= set(df.columns)
