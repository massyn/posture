import json
from pathlib import Path

import pandas as pd

from posture.collectors.sentinelone import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "sentinelone"

AGENTS_MANIFEST = MANIFEST["agents"]
THREATS_MANIFEST = MANIFEST["threats"]
SITES_MANIFEST = MANIFEST["sites"]
INSTALLED_APPLICATIONS_MANIFEST = MANIFEST["installed_applications"]


def _load(name: str) -> list[dict] | dict:
    return json.loads((FIXTURES / name).read_text())


def test_agents_page() -> None:
    df = parse(_load("agents_page.json"), AGENTS_MANIFEST, resource="agents")

    assert len(df) == 2
    assert df.loc[0, "agent_id"] == "1"
    assert df.loc[0, "computer_name"] == "WIN-1"
    assert bool(df.loc[0, "is_active"]) is True
    assert df["last_active_date"].dtype == "datetime64[us, UTC]"
    assert pd.isna(df.loc[1, "last_active_date"])  # absent in fixture
    assert pd.isna(df.loc[1, "site_id"])  # absent in fixture


def test_threats_page() -> None:
    df = parse(_load("threats_page.json"), THREATS_MANIFEST, resource="threats")

    assert len(df) == 1
    assert df.loc[0, "threat_id"] == "threat-1"
    assert df.loc[0, "classification"] == "Malware"
    assert df.loc[0, "file_size"] == 1024
    assert df.loc[0, "agent_uuid"] == "uuid-1"


def test_sites_page() -> None:
    df = parse(_load("sites_page.json"), SITES_MANIFEST, resource="sites")

    assert len(df) == 1
    assert df.loc[0, "site_id"] == "site-1"
    assert df.loc[0, "state"] == "active"


def test_installed_applications_page() -> None:
    df = parse(
        _load("installed_applications_page.json"),
        INSTALLED_APPLICATIONS_MANIFEST,
        resource="installed_applications",
    )

    assert len(df) == 1
    assert df.loc[0, "name"] == "Chrome"
    assert df.loc[0, "publisher"] == "Google LLC"
