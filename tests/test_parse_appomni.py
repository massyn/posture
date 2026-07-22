import json
from pathlib import Path

import pandas as pd

from posture.collectors.appomni import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "appomni"

MONITORED_SERVICES_MANIFEST = MANIFEST["monitored_services"]
POLICIES_MANIFEST = MANIFEST["policies"]
OPEN_POLICY_ISSUES_MANIFEST = MANIFEST["open_policy_issues"]
UNIFIED_IDENTITIES_MANIFEST = MANIFEST["unified_identities"]


def _load(name: str) -> list[dict]:
    payload = json.loads((FIXTURES / name).read_text())
    return payload if isinstance(payload, list) else payload["results"]


def test_monitored_services_page() -> None:
    df = parse(
        _load("monitored_services_page.json"),
        MONITORED_SERVICES_MANIFEST,
        resource="monitored_services",
    )

    assert len(df) == 2
    assert df.loc[0, "name"] == "Salesforce Prod"
    assert df.loc[0, "app_type"] == "salesforce"
    assert df["created"].dtype == "datetime64[ns, UTC]"
    assert pd.isna(df.loc[1, "instance_url"])  # absent in fixture


def test_policies_page() -> None:
    df = parse(_load("policies_page.json"), POLICIES_MANIFEST, resource="policies")

    assert len(df) == 2
    assert df.loc[0, "policy_type"] == "identity"
    assert bool(df.loc[0, "is_reference"]) is True
    assert bool(df.loc[1, "enabled"]) is False
    assert pd.isna(df.loc[1, "description"])


def test_open_policy_issues_page() -> None:
    df = parse(
        _load("open_policy_issues_page.json"),
        OPEN_POLICY_ISSUES_MANIFEST,
        resource="open_policy_issues",
    )

    assert len(df) == 2
    assert df.loc[0, "policy_id"] == "pol-1"
    assert df.loc[0, "monitored_service_name"] == "Salesforce Prod"
    assert pd.isna(df.loc[1, "policy_id"])  # no policy nested on this issue


def test_unified_identities_page() -> None:
    df = parse(
        _load("unified_identities_page.json"),
        UNIFIED_IDENTITIES_MANIFEST,
        resource="unified_identities",
    )

    assert len(df) == 2
    assert df.loc[0, "identity_type"] == "human"
    assert df.loc[0, "num_users_linked"] == 3
    assert pd.isna(df.loc[1, "risk_score"])
