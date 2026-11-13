import json
from pathlib import Path

import pandas as pd

from posture.collectors.dependency_track import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "dependency_track"


def test_project_findings_page() -> None:
    raw = json.loads((FIXTURES / "project_findings_page.json").read_text())
    df = parse(raw, MANIFEST["project_findings"], resource="project_findings")

    assert len(df) == 2
    assert df.loc[0, "project_uuid"] == "proj-1"
    assert df.loc[0, "component_name"] == "log4j-core"
    assert df.loc[0, "vuln_id"] == "CVE-2021-44228"
    assert df.loc[0, "severity"] == "CRITICAL"
    assert df.loc[0, "cvss_v3_base_score"] == 10.0
    assert df.loc[0, "analysis_state"] == "EXPLOITABLE"
    assert bool(df.loc[1, "is_suppressed"]) is True
    assert json.loads(df.loc[0, "cwes"])[0]["cweId"] == 502
    # epoch-millisecond dates become tz-aware UTC datetimes
    assert df["published"].dtype == "datetime64[us, UTC]"
    assert df.loc[0, "published"] == pd.Timestamp("2021-12-10", tz="UTC")
    assert pd.isna(df.loc[1, "published"])
