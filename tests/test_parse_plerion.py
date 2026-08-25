import json
from pathlib import Path

import pandas as pd

from posture.collectors.plerion import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "plerion"

FINDINGS_MANIFEST = MANIFEST["findings"]
ASSETS_MANIFEST = MANIFEST["assets"]
VULNERABILITIES_MANIFEST = MANIFEST["vulnerabilities"]


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_findings_page() -> None:
    df = parse(_load("findings_page.json"), FINDINGS_MANIFEST, resource="findings")

    assert len(df) == 1
    row = df.loc[0]
    assert row["detection_id"] == "PLERION-AWS-16"
    assert row["status"] == "FAILED"
    assert row["modified_severity_level"] == "CRITICAL"
    assert bool(row["is_exempted"]) is False
    assert json.loads(row["resource_tags"])[0]["Key"] == "Public"
    assert pd.isna(row["attack_paths"])  # null in the fixture
    assert df["first_observed_at"].dtype == "datetime64[us, UTC]"
    assert df["sla_due_at"].dtype == "datetime64[us, UTC]"


def test_assets_page() -> None:
    df = parse(_load("assets_page.json"), ASSETS_MANIFEST, resource="assets")

    assert len(df) == 1
    row = df.loc[0]
    assert row["resource_type"] == "AWS::EC2::Instance"
    assert bool(row["is_publicly_exposed"]) is False
    assert row["number_of_critical_vulnerabilities"] == 5
    assert row["risk_score"] == 9.36
    assert row["vulnerability_score"] == 9.0
    assert pd.isna(row["operating_system"])  # null in the fixture
    assert df["last_scanned_at"].dtype == "datetime64[us, UTC]"


def test_vulnerabilities_page() -> None:
    df = parse(
        _load("vulnerabilities_page.json"),
        VULNERABILITIES_MANIFEST,
        resource="vulnerabilities",
    )

    assert len(df) == 2
    row = df.loc[0]
    assert row["vulnerability_id"] == "CVE-2022-22965"
    assert bool(row["has_kev"]) is True
    assert row["severity_level_value"] == 4
    assert json.loads(row["packages"])[0]["packageName"] == "sample-package"
    assert json.loads(row["known_exploit"])["cveID"] == "CVE-2022-22965"
    assert df["published_date"].dtype == "datetime64[us, UTC]"

    # second row exercises nulls: no known exploit, no target name
    assert pd.isna(df.loc[1, "known_exploit"])
    assert pd.isna(df.loc[1, "target_name"])
