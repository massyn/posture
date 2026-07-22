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
    assert df["created"].dtype == "datetime64[ns, UTC]"
    assert pd.isna(df.loc[1, "target_reference"])  # absent in fixture


def test_issues_page() -> None:
    df = parse(_load("issues_page.json"), ISSUES_MANIFEST, resource="issues")

    assert len(df) == 2
    assert df.loc[0, "project_id"] == "proj-1"
    assert df.loc[0, "effective_severity_level"] == "high"
    assert bool(df.loc[1, "ignored"]) is True
    assert pd.isna(df.loc[1, "project_id"])  # no scan_item relationship on this issue
