import json
from pathlib import Path

from posture.collectors.defender_for_cloud import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "defender_for_cloud"


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_assessments_page() -> None:
    df = parse(
        _load("assessments_page.json"),
        MANIFEST["assessments"],
        resource="assessments",
    )

    assert len(df) == 2
    assert df.loc[0, "status_code"] == "Unhealthy"
    assert df.loc[0, "severity"] == "Medium"
    assert df.loc[0, "resource_id"].endswith("vm-web-1")
    assert df.loc[1, "status_code"] == "Healthy"
    assert isinstance(df.loc[0, "categories"], str)


def test_secure_scores_page() -> None:
    df = parse(
        _load("secure_scores_page.json"),
        MANIFEST["secure_scores"],
        resource="secure_scores",
    )

    assert len(df) == 1
    assert df.loc[0, "name"] == "ascScore"
    assert float(df.loc[0, "current_score"]) == 28.0
    assert int(df.loc[0, "max_score"]) == 55
