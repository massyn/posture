import json
from pathlib import Path

import pandas as pd

from posture.collectors.knowbe4 import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "knowbe4"

ENROLLMENTS_MANIFEST = MANIFEST["training_enrollments"]
PSTS_MANIFEST = MANIFEST["psts"]
PST_RECIPIENTS_MANIFEST = MANIFEST["pst_recipients"]


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_training_enrollments_page() -> None:
    df = parse(
        _load("enrollments_page.json"),
        ENROLLMENTS_MANIFEST,
        resource="training_enrollments",
    )

    assert len(df) == 2
    assert df.loc[0, "enrollment_id"] == 101
    assert df.loc[0, "user_id"] == 501
    assert df.loc[0, "user_email"] == "alice@example.com"
    assert df.loc[0, "status"] == "Passed"
    assert df["enrollment_date"].dtype == "datetime64[ns, UTC]"
    assert pd.isna(df.loc[1, "start_date"])  # null in fixture
    assert pd.isna(df.loc[1, "completion_date"])


def test_psts_page() -> None:
    df = parse(_load("psts_page.json"), PSTS_MANIFEST, resource="psts")

    assert len(df) == 2
    assert df.loc[0, "pst_id"] == 301
    assert df.loc[0, "phish_prone_percentage"] == 12.5
    assert df.loc[0, "clicked_count"] == 12
    assert df["started_at"].dtype == "datetime64[ns, UTC]"
    assert pd.isna(df.loc[1, "started_at"])  # null in fixture
    assert pd.isna(df.loc[1, "phish_prone_percentage"])


def test_pst_recipients_page() -> None:
    records = _load("pst_recipients_page.json")
    for record in records:
        record["_pst_id"] = 301

    df = parse(records, PST_RECIPIENTS_MANIFEST, resource="pst_recipients")

    assert len(df) == 2
    assert df.loc[0, "pst_id"] == 301
    assert df.loc[0, "user_email"] == "alice@example.com"
    assert df.loc[0, "template_name"] == "Invoice Phish Q1"
    assert df["clicked_at"].dtype == "datetime64[ns, UTC]"
    assert pd.isna(df.loc[1, "clicked_at"])  # bob didn't click
    assert df.loc[1, "reported_at"] is not pd.NaT  # bob reported it
