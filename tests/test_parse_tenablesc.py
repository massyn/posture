import json
from pathlib import Path

import pandas as pd

from posture.collectors.tenablesc import MANIFEST, _expand_ip_range
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "tenablesc"

VULNERABILITIES_MANIFEST = MANIFEST["vulnerabilities"]
HOSTS_MANIFEST = MANIFEST["hosts"]
ASSETS_MANIFEST = MANIFEST["assets"]
ASSET_IPS_MANIFEST = MANIFEST["asset_ips"]


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_vulnerabilities_page() -> None:
    df = parse(
        _load("vulnerabilities_page.json"),
        VULNERABILITIES_MANIFEST,
        resource="vulnerabilities",
    )

    assert len(df) == 2
    assert df.loc[0, "severity"] == "High"
    assert df.loc[0, "severity_id"] == 3
    assert df.loc[0, "repository_name"] == "Primary Repo"
    assert df["first_seen"].dtype == "datetime64[ns, UTC]"
    assert df.loc[0, "cvss3_base_score"] == 8.1
    assert pd.isna(df.loc[1, "cvss3_base_score"])  # absent in fixture


def test_hosts_page() -> None:
    df = parse(_load("hosts_page.json"), HOSTS_MANIFEST, resource="hosts")

    assert len(df) == 2
    assert df.loc[0, "ip_address"] == "10.0.0.5"
    assert df.loc[0, "repository_name"] == "Primary Repo"
    assert df.loc[1, "net_bios"] == "HOST2"
    assert df["last_seen"].dtype == "datetime64[ns, UTC]"


def test_assets_page() -> None:
    df = parse(_load("assets_page.json"), ASSETS_MANIFEST, resource="assets")

    assert len(df) == 2
    assert df.loc[0, "name"] == "Non Crowdstrike Assets"
    assert df.loc[0, "owner_name"] == "Alice Smith"
    assert df.loc[0, "ip_count"] == 2


def test_asset_ips_page() -> None:
    df = parse(_load("asset_ips_page.json"), ASSET_IPS_MANIFEST, resource="asset_ips")

    assert len(df) == 2
    assert df.loc[0, "ip"] == "10.8.16.26"
    assert df.loc[1, "ip"] == "10.8.16.27"
    assert df.loc[0, "asset_name"] == "Non Crowdstrike Assets"


def test_expand_ip_range_single_ip() -> None:
    assert _expand_ip_range("10.0.0.5") == ["10.0.0.5"]


def test_expand_ip_range_last_octet_shorthand() -> None:
    assert _expand_ip_range("10.8.16.26-27") == ["10.8.16.26", "10.8.16.27"]


def test_expand_ip_range_full_range() -> None:
    assert _expand_ip_range("10.0.0.254-10.0.1.1") == [
        "10.0.0.254",
        "10.0.0.255",
        "10.0.1.0",
        "10.0.1.1",
    ]
