import json
from pathlib import Path

import pandas as pd

from posture.collectors.gcp_security_command_center import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "gcp_security_command_center"


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_findings_page() -> None:
    df = parse(_load("findings_page.json"), MANIFEST["findings"], resource="findings")

    assert len(df) == 2
    assert df.loc[0, "category"] == "PUBLIC_IP_ADDRESS"
    assert df.loc[0, "severity"] == "HIGH"
    assert df.loc[0, "cve_id"] == "CVE-2024-1234"
    assert float(df.loc[0, "cvss_base_score"]) == 8.1
    assert df.loc[0, "resource_display_name"] == "instance-1"
    assert df["event_time"].dtype == "datetime64[us, UTC]"
    assert isinstance(df.loc[0, "source_properties"], str)
    assert pd.isna(df.loc[1, "cve_id"])
