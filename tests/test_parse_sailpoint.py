import json
from pathlib import Path

import pandas as pd

from posture.collectors.sailpoint import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "sailpoint"

IDENTITIES_MANIFEST = MANIFEST["identities"]
ACCOUNTS_MANIFEST = MANIFEST["accounts"]
ACCESS_PROFILES_MANIFEST = MANIFEST["access_profiles"]
ROLES_MANIFEST = MANIFEST["roles"]


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_identities_page() -> None:
    df = parse(
        _load("identities_page.json"), IDENTITIES_MANIFEST, resource="identities"
    )

    assert len(df) == 2
    assert df.loc[0, "display_name"] == "Alice Smith"
    assert df.loc[0, "identity_profile_id"] == "ip-1"
    assert df.loc[0, "manager_name"] == "Bob Jones"
    assert bool(df.loc[0, "is_manager"]) is True
    assert df["created"].dtype == "datetime64[ns, UTC]"
    assert pd.isna(df.loc[1, "identity_profile_id"])  # absent in fixture


def test_accounts_page() -> None:
    df = parse(_load("accounts_page.json"), ACCOUNTS_MANIFEST, resource="accounts")

    assert len(df) == 2
    assert df.loc[0, "identity_id"] == "id-1"
    assert bool(df.loc[0, "has_entitlements"]) is True
    assert bool(df.loc[1, "system_account"]) is True
    assert pd.isna(df.loc[1, "identity_id"])  # uncorrelated account


def test_access_profiles_page() -> None:
    df = parse(
        _load("access_profiles_page.json"),
        ACCESS_PROFILES_MANIFEST,
        resource="access_profiles",
    )

    assert len(df) == 2
    assert df.loc[0, "owner_name"] == "Bob Jones"
    assert df.loc[0, "source_name"] == "Active Directory"
    assert bool(df.loc[1, "enabled"]) is False
    assert pd.isna(df.loc[1, "owner_id"])


def test_roles_page() -> None:
    df = parse(_load("roles_page.json"), ROLES_MANIFEST, resource="roles")

    assert len(df) == 2
    assert df.loc[0, "owner_id"] == "id-2"
    assert bool(df.loc[0, "requestable"]) is True
    assert pd.isna(df.loc[1, "owner_id"])
