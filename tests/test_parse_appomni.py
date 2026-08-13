import json
from pathlib import Path

import pandas as pd

from posture.collectors.appomni import MANIFEST, AppOmniCollector
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "appomni"

MONITORED_SERVICES_MANIFEST = MANIFEST["monitored_services"]
POLICIES_MANIFEST = MANIFEST["policies"]
OPEN_POLICY_ISSUES_MANIFEST = MANIFEST["open_policy_issues"]
UNIFIED_IDENTITIES_MANIFEST = MANIFEST["unified_identities"]
POLICY_RISK_SUMMARY_MANIFEST = MANIFEST["policy_risk_summary"]


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
    assert df.loc[0, "score"] == 15
    assert bool(df.loc[1, "has_errors"]) is True
    assert df["created"].dtype == "datetime64[us, UTC]"
    assert pd.isna(df.loc[1, "score"])  # absent in fixture


def test_policies_page() -> None:
    df = parse(_load("policies_page.json"), POLICIES_MANIFEST, resource="policies")

    assert len(df) == 2
    assert df.loc[0, "policy_type"] == "identity"
    assert bool(df.loc[0, "is_reference"]) is True
    assert bool(df.loc[1, "enabled"]) is False
    assert pd.isna(df.loc[1, "description"])


def test_open_policy_issues_page() -> None:
    records = _load("open_policy_issues_page.json")
    service_org_names = {"svc-1": "Salesforce Prod", "svc-2": "Workday Prod"}
    for record in records:
        record["_monitored_service_name"] = service_org_names.get(
            record.get("service_org_id")
        )

    df = parse(records, OPEN_POLICY_ISSUES_MANIFEST, resource="open_policy_issues")

    assert len(df) == 2
    assert df.loc[0, "policy_id"] == "pol-1"
    assert df.loc[0, "monitored_service_name"] == "Salesforce Prod"
    assert df.loc[0, "severity"] == "50"
    assert df.loc[0, "rule_name"] == "MFA Not Enforced For All Users"
    assert df.loc[0, "rule_posture_category"] == "authentication"
    assert df.loc[1, "monitored_service_name"] == "Workday Prod"
    assert pd.isna(df.loc[1, "policy_id"])  # no policy on this issue
    assert pd.isna(df.loc[1, "rule_name"])  # no rule on this issue


def test_policy_risk_summary_page() -> None:
    records = _load("policy_risk_summary_page.json")
    risk_level_names = ("Informational", "Low", "Medium", "High", "Critical")
    for record in records:
        record["_total_rules_count"] = sum(
            counts.get("rules", 0)
            for counts in (record.get("rule_type_counts") or {}).values()
        )
        risk_levels = {
            level["name"]: level.get("risk_count", 0)
            for level in (record.get("risk_statistics") or {}).get("risk_levels", [])
        }
        for name in risk_level_names:
            record[f"_risk_{name.lower()}_count"] = risk_levels.get(name, 0)
        record["_risk_score"] = (record.get("risk_statistics") or {}).get("risk_score")

    df = parse(
        records, POLICY_RISK_SUMMARY_MANIFEST, resource="policy_risk_summary"
    )

    assert len(df) == 2
    assert df.loc[0, "open_issues_count"] == 92
    assert df.loc[0, "total_rules_count"] == 79
    assert df.loc[0, "risk_score"] == 75
    assert df.loc[0, "risk_high_count"] == 31
    assert json.loads(df.loc[0, "monitored_service_ids"]) == ["svc-1"]
    assert df.loc[1, "total_rules_count"] == 0
    assert pd.isna(df.loc[1, "risk_score"])  # empty risk_statistics in fixture


def test_fetch_policy_detail_stringifies_monitored_service_ids() -> None:
    collector = AppOmniCollector({"access_token": "tok", "instance": "acme"})

    class _FakeResponse:
        def json(self) -> dict:
            return {
                "id": 143202,
                "monitored_services": [549, 550],
                "rule_type_counts": {},
                "risk_statistics": {},
            }

    collector._get = lambda url, params=None: _FakeResponse()

    record = collector._fetch_policy_detail(143202)

    assert record["monitored_services"] == ["549", "550"]


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
