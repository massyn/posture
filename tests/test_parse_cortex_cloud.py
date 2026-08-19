import json
from pathlib import Path

import pandas as pd

from posture.collectors.cortex_cloud import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "cortex_cloud"

ASSETS_MANIFEST = MANIFEST["assets"]
ISSUES_MANIFEST = MANIFEST["issues"]


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_assets_page() -> None:
    df = parse(_load("assets_page.json"), ASSETS_MANIFEST, resource="assets")

    assert len(df) == 2
    assert df.loc[0, "name"] == "web-server-01"
    assert df.loc[0, "provider"] == "AWS"
    assert df.loc[0, "type_class"] == "Compute"
    assert bool(df.loc[0, "is_publicly_accessible"]) is True
    assert df.loc[0, "critical_issues"] == 2
    assert json.loads(df.loc[0, "issues_breakdown"])["critical"] == 2
    assert df["first_observed"].dtype == "datetime64[us, UTC]"
    assert pd.isna(df.loc[1, "cloud_region"])  # absent in fixture


def test_issues_page() -> None:
    df = parse(_load("issues_page.json"), ISSUES_MANIFEST, resource="issues")

    assert len(df) == 2
    assert df.loc[0, "severity"] == "HIGH"
    assert df.loc[0, "detection_method"] == "CAS_SECRET_SCANNER"
    assert df.loc[0, "status_progress"] == "New"
    assert bool(df.loc[0, "is_starred"]) is True
    assert json.loads(df.loc[0, "asset_ids"]) == ["asset-1"]
    assert df["observation_time"].dtype == "datetime64[us, UTC]"
    assert df.loc[1, "severity"] == "CRITICAL"
    assert pd.isna(df.loc[1, "description"])  # absent in fixture
