import json
from pathlib import Path

import pandas as pd

from posture.collectors.snyk import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "snyk"

ORGANIZATIONS_MANIFEST = MANIFEST["organizations"]
MEMBERS_MANIFEST = MANIFEST["members"]
PROJECTS_MANIFEST = MANIFEST["projects"]
ISSUES_MANIFEST = MANIFEST["issues"]
TARGETS_MANIFEST = MANIFEST["targets"]
AGGREGATED_ISSUES_MANIFEST = MANIFEST["aggregated_issues"]


def _load(name: str) -> list[dict]:
    payload = json.loads((FIXTURES / name).read_text())
    return payload if isinstance(payload, list) else payload["data"]


def test_organizations_page() -> None:
    df = parse(
        _load("organizations_page.json"),
        ORGANIZATIONS_MANIFEST,
        resource="organizations",
    )

    assert len(df) == 2
    assert df.loc[0, "name"] == "Acme Corp"
    assert df.loc[0, "slug"] == "acme-corp"
    assert df.loc[0, "group_id"] == "group-1"
    assert pd.isna(df.loc[1, "group_id"])  # no group relationship on this org


def test_members_page() -> None:
    df = parse(_load("members_page.json"), MEMBERS_MANIFEST, resource="members")

    assert len(df) == 2
    assert df.loc[0, "org_id"] == "org-1"
    assert df.loc[0, "role"] == "admin"
    assert bool(df.loc[0, "active"]) is True
    assert bool(df.loc[1, "active"]) is False


def test_projects_page() -> None:
    df = parse(_load("projects_page.json"), PROJECTS_MANIFEST, resource="projects")

    assert len(df) == 2
    assert df.loc[0, "org_id"] == "org-1"
    assert df.loc[0, "type"] == "npm"
    assert df["created"].dtype == "datetime64[us, UTC]"
    assert pd.isna(df.loc[1, "target_reference"])  # absent in fixture
    assert df.loc[0, "tags"] == '[{"key": "team", "value": "platform"}]'
    assert df.loc[0, "target_id"] == "target-1"
    assert pd.isna(df.loc[1, "target_id"])  # no target relationship on this project


def test_issues_page() -> None:
    df = parse(_load("issues_page.json"), ISSUES_MANIFEST, resource="issues")

    assert len(df) == 2
    assert df.loc[0, "project_id"] == "proj-1"
    assert df.loc[0, "effective_severity_level"] == "high"
    assert bool(df.loc[1, "ignored"]) is True
    assert pd.isna(df.loc[1, "project_id"])  # no scan_item relationship on this issue


def test_targets_page() -> None:
    df = parse(_load("targets_page.json"), TARGETS_MANIFEST, resource="targets")

    assert len(df) == 2
    assert df.loc[0, "org_id"] == "org-1"
    assert df.loc[0, "display_name"] == "acme/webapp"
    assert df.loc[0, "url"] == "http://github.com/acme/webapp"
    assert bool(df.loc[0, "is_private"]) is True
    assert df.loc[0, "integration_type"] == "github"
    assert pd.isna(df.loc[1, "integration_type"])  # no integration relationship


def test_aggregated_issues_page() -> None:
    payload = json.loads((FIXTURES / "aggregated_issues_page.json").read_text())
    df = parse(
        payload["issues"], AGGREGATED_ISSUES_MANIFEST, resource="aggregated_issues"
    )

    assert len(df) == 2
    assert df.loc[0, "org_id"] == "org-1"
    assert df.loc[0, "project_id"] == "proj-1"
    assert df.loc[0, "severity"] == "high"
    assert df.loc[0, "exploit_maturity"] == "mature"
    assert df.loc[0, "cvss_score"] == 7.5
    assert df.loc[0, "cve_ids"] == '["CVE-2023-44487"]'
    assert bool(df.loc[0, "is_fixable"]) is True
    assert bool(df.loc[1, "is_patched"]) is True
    assert pd.isna(df.loc[1, "cvss_v3_vector"])  # absent in fixture
