import json
from pathlib import Path

import pandas as pd

from posture.collectors.recorded_future import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "recorded_future"

ALERTS_MANIFEST = MANIFEST["alerts"]
ALERT_HITS_MANIFEST = MANIFEST["alert_hits"]
VULNERABILITY_RISKLIST_MANIFEST = MANIFEST["vulnerability_risklist"]


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_alerts_page() -> None:
    df = parse(_load("alerts_page.json"), ALERTS_MANIFEST, resource="alerts")

    assert list(df["id"]) == ["alert-1", "alert-2"]
    assert df.loc[0, "rule_name"] == "Vulnerability Intelligence from Insikt Group"
    assert df.loc[0, "status"] == "no-action"
    assert df.loc[1, "assignee"] == "alice@example.com"
    assert df.loc[1, "note"] == "handled"
    assert pd.isna(df.loc[0, "note"])  # null in fixture


def test_alert_hits_explodes_nested_hits() -> None:
    df = parse(_load("alerts_page.json"), ALERT_HITS_MANIFEST, resource="alert_hits")

    # alert-2 has an empty hits list, so only alert-1's single hit survives.
    assert len(df) == 1
    assert df.loc[0, "alert_id"] == "alert-1"
    assert df.loc[0, "hit_id"] == "hit-1"
    assert df.loc[0, "document_title"] == "New exploit for CVE-2024-1234"
    assert df.loc[0, "document_source_name"] == "Example Source"
    assert json.loads(df.loc[0, "entities"]) == [
        {"id": "entity-1", "name": "CVE-2024-1234", "type": "CyberVulnerability"}
    ]


def test_vulnerability_risklist_page() -> None:
    df = parse(
        _load("vulnerability_risklist_records.json"),
        VULNERABILITY_RISKLIST_MANIFEST,
        resource="vulnerability_risklist",
    )

    assert len(df) == 2
    assert df.loc[0, "name"] == "CVE-2024-1234"
    assert int(df.loc[0, "risk"]) == 89
    assert df.loc[0, "risk_string"] == "8/25"
    evidence = json.loads(df.loc[0, "evidence_details"])
    assert evidence[0]["Rule"] == "Recently Active in Underground Communities"
    assert json.loads(df.loc[1, "evidence_details"]) == []
