import json
from pathlib import Path

import pandas as pd

from posture.collectors.tenableio import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "tenableio"

ASSETS_MANIFEST = MANIFEST["assets"]
VULNS_MANIFEST = MANIFEST["vulnerabilities"]


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_assets_page() -> None:
    df = parse(_load("assets_page.json"), ASSETS_MANIFEST, resource="assets")

    assert len(df) == 2
    assert df.loc[0, "asset_id"] == "asset-1"
    assert df.loc[0, "hostname"] == "host1.example.com"
    assert df.loc[0, "mac_address"] == "00:11:22:33:44:55"
    assert bool(df.loc[0, "has_agent"]) is True
    assert df["first_seen"].dtype == "datetime64[ns, UTC]"
    assert pd.isna(df.loc[1, "first_seen"])
    assert pd.isna(df.loc[1, "hostname"])


def test_vulnerabilities_page() -> None:
    df = parse(_load("vulns_page.json"), VULNS_MANIFEST, resource="vulnerabilities")

    assert len(df) == 2
    assert df.loc[0, "asset_uuid"] == "asset-uuid-1"
    assert df.loc[0, "plugin_id"] == 12345
    assert df.loc[0, "severity"] == "high"
    assert df.loc[0, "cvss_base_score"] == 7.5
    assert json.loads(df.loc[0, "cve"]) == ["CVE-2026-0001", "CVE-2026-0002"]
    assert df.loc[0, "port"] == 443
    assert pd.isna(df.loc[1, "port"])
