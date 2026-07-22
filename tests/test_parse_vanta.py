import json
from pathlib import Path

import pandas as pd

from posture.collectors.vanta import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "vanta"

CONTROLS_MANIFEST = MANIFEST["controls"]
PEOPLE_MANIFEST = MANIFEST["people"]
VULNERABILITIES_MANIFEST = MANIFEST["vulnerabilities"]


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_controls_page() -> None:
    df = parse(_load("controls_page.json"), CONTROLS_MANIFEST, resource="controls")

    assert len(df) == 2
    assert df.loc[0, "name"] == "Access control policy"
    assert df.loc[0, "question"] == "Does the company have an access control policy?"
    assert df["created_at"].dtype == "datetime64[ns, UTC]"
    assert pd.isna(df.loc[0, "deleted_at"])  # not deleted
    assert not pd.isna(df.loc[1, "deleted_at"])


def test_people_page() -> None:
    df = parse(_load("people_page.json"), PEOPLE_MANIFEST, resource="people")

    assert len(df) == 2
    assert df.loc[0, "email"] == "alice@example.com"
    assert bool(df.loc[0, "is_vanta_owner"]) is True
    assert bool(df.loc[1, "is_vanta_owner"]) is False
    assert df.loc[1, "employment_status"] == "terminated"
    assert pd.isna(df.loc[0, "end_date"])  # still employed


def test_vulnerabilities_page() -> None:
    df = parse(
        _load("vulnerabilities_page.json"),
        VULNERABILITIES_MANIFEST,
        resource="vulnerabilities",
    )

    assert len(df) == 1
    assert df.loc[0, "severity"] == "high"
    assert df.loc[0, "cve"] == "CVE-2024-0001"
    assert df["detected_at"].dtype == "datetime64[ns, UTC]"
