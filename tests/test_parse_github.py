import json
from pathlib import Path

import pandas as pd

from posture.collectors.github import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "github"

ORGANIZATIONS_MANIFEST = MANIFEST["organizations"]
REPOSITORIES_MANIFEST = MANIFEST["repositories"]
MEMBERS_MANIFEST = MANIFEST["members"]
CODE_SCANNING_ALERTS_MANIFEST = MANIFEST["code_scanning_alerts"]
DEPENDABOT_ALERTS_MANIFEST = MANIFEST["dependabot_alerts"]
BRANCHES_MANIFEST = MANIFEST["branches"]
BRANCH_PROTECTION_RULES_MANIFEST = MANIFEST["branch_protection_rules"]


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_organizations_page() -> None:
    df = parse(
        _load("organizations_page.json"),
        ORGANIZATIONS_MANIFEST,
        resource="organizations",
    )

    assert len(df) == 2
    assert df.loc[0, "login"] == "acme-corp"
    assert df.loc[0, "description"] == "Acme Corp org"
    assert pd.isna(df.loc[1, "description"])


def test_repositories_page() -> None:
    df = parse(
        _load("repositories_page.json"),
        REPOSITORIES_MANIFEST,
        resource="repositories",
    )

    assert len(df) == 2
    assert df.loc[0, "org"] == "acme-corp"
    assert df.loc[0, "full_name"] == "acme-corp/webapp"
    assert bool(df.loc[0, "private"]) is True
    assert df.loc[0, "license_name"] == "MIT License"
    assert df["created_at"].dtype == "datetime64[us, UTC]"
    assert bool(df.loc[1, "archived"]) is True
    assert pd.isna(df.loc[1, "license_name"])  # no license on this repo


def test_members_page() -> None:
    df = parse(_load("members_page.json"), MEMBERS_MANIFEST, resource="members")

    assert len(df) == 2
    assert df.loc[0, "org"] == "acme-corp"
    assert df.loc[0, "login"] == "alice"
    assert bool(df.loc[0, "site_admin"]) is False
    assert bool(df.loc[1, "site_admin"]) is True


def test_code_scanning_alerts_page() -> None:
    df = parse(
        _load("code_scanning_alerts_page.json"),
        CODE_SCANNING_ALERTS_MANIFEST,
        resource="code_scanning_alerts",
    )

    assert len(df) == 2
    assert df.loc[0, "repo"] == "webapp"
    assert df.loc[0, "rule_security_severity_level"] == "critical"
    assert df.loc[0, "location_path"] == "app/db.py"
    assert pd.isna(df.loc[0, "dismissed_by"])
    assert df.loc[1, "dismissed_by"] == "alice"
    assert df.loc[1, "state"] == "dismissed"


def test_dependabot_alerts_page() -> None:
    df = parse(
        _load("dependabot_alerts_page.json"),
        DEPENDABOT_ALERTS_MANIFEST,
        resource="dependabot_alerts",
    )

    assert len(df) == 2
    assert df.loc[0, "package_name"] == "requests"
    assert df.loc[0, "package_ecosystem"] == "pip"
    assert df.loc[0, "first_patched_version"] == "2.31.0"
    assert df.loc[1, "state"] == "fixed"
    assert pd.isna(df.loc[1, "cve_id"])


def test_branches_page() -> None:
    df = parse(_load("branches_page.json"), BRANCHES_MANIFEST, resource="branches")

    assert len(df) == 2
    assert df.loc[0, "name"] == "main"
    assert bool(df.loc[0, "protected"]) is True
    assert bool(df.loc[1, "protected"]) is False
    assert df.loc[0, "commit_sha"] == "abc123"


def test_branch_protection_rules_page() -> None:
    df = parse(
        _load("branch_protection_rules_page.json"),
        BRANCH_PROTECTION_RULES_MANIFEST,
        resource="branch_protection_rules",
    )

    assert len(df) == 2
    assert df.loc[0, "branch"] == "main"
    assert df.loc[0, "type"] == "pull_request"
    assert df.loc[0, "parameters"] == '{"required_approving_review_count": 2}'
    assert df.loc[1, "type"] == "deletion"
