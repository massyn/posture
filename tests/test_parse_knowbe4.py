import json
from pathlib import Path

import pandas as pd

from posture.collectors.knowbe4 import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "knowbe4"

ENROLLMENTS_MANIFEST = MANIFEST["training_enrollments"]


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
