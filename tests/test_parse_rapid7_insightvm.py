import json
from pathlib import Path

from posture.collectors.rapid7_insightvm import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "rapid7_insightvm"


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_assets_page() -> None:
    df = parse(_load("assets_page.json"), MANIFEST["assets"], resource="assets")

    assert len(df) == 1
    assert df.loc[0, "host_name"] == "web-prod-01"
    assert bool(df.loc[0, "assessed_for_vulnerabilities"]) is True
    assert float(df.loc[0, "risk_score"]) == 12843.7
    assert int(df.loc[0, "critical_vulnerabilities"]) == 3
    assert df["last_assessed_for_vulnerabilities"].dtype == "datetime64[us, UTC]"
    assert isinstance(df.loc[0, "tags"], str)


def test_vulnerabilities_page() -> None:
    df = parse(
        _load("vulnerabilities_page.json"),
        MANIFEST["vulnerabilities"],
        resource="vulnerabilities",
    )

    assert len(df) == 1
    assert df.loc[0, "severity"] == "Critical"
    assert float(df.loc[0, "cvss_v3_score"]) == 9.8
    assert df["published"].dtype == "datetime64[us, UTC]"
    assert "CVE-2024-0001" in df.loc[0, "cves"]
