import json
from pathlib import Path

import pandas as pd

from posture.collectors.okta import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "okta"

USERS_MANIFEST = MANIFEST["users"]
DEVICES_MANIFEST = MANIFEST["devices"]
DEVICE_USERS_MANIFEST = MANIFEST["device_users"]
GROUPS_MANIFEST = MANIFEST["groups"]
GROUP_MEMBERS_MANIFEST = MANIFEST["group_members"]
USER_FACTORS_MANIFEST = MANIFEST["user_factors"]
USER_ROLES_MANIFEST = MANIFEST["user_roles"]


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_users_page() -> None:
    df = parse(_load("users_page.json"), USERS_MANIFEST, resource="users")

    assert len(df) == 2
    assert df.loc[0, "profile_login"] == "alice@example.com"
    assert df.loc[0, "profile_department"] == "Engineering"
    assert df.loc[0, "type_id"] == "type-1"
    assert df["created"].dtype == "datetime64[us, UTC]"
    assert pd.isna(df.loc[1, "activated"])  # absent in fixture


def test_devices_page() -> None:
    df = parse(_load("devices_page.json"), DEVICES_MANIFEST, resource="devices")

    assert len(df) == 2
    assert bool(df.loc[0, "profile_registered"]) is True
    assert bool(df.loc[1, "profile_registered"]) is False
    assert df.loc[0, "resourcedisplayname_value"] == "Alice's MacBook"
    assert pd.isna(df.loc[1, "resourcedisplayname_value"])  # absent in fixture


def test_device_users_page() -> None:
    df = parse(
        _load("device_users_page.json"), DEVICE_USERS_MANIFEST, resource="device_users"
    )

    assert len(df) == 1
    assert df.loc[0, "device_id"] == "device-1"  # injected _device_id
    assert df.loc[0, "user_id"] == "user-1"
    assert df.loc[0, "user_profile_login"] == "alice@example.com"
    assert df["user_created"].dtype == "datetime64[us, UTC]"


def test_groups_page() -> None:
    df = parse(_load("groups_page.json"), GROUPS_MANIFEST, resource="groups")

    assert len(df) == 2
    assert df.loc[0, "profile_name"] == "Engineering"
    assert df.loc[0, "type"] == "OKTA_GROUP"
    assert pd.isna(df.loc[1, "profile_description"])  # absent in fixture


def test_group_members_page() -> None:
    df = parse(
        _load("group_members_page.json"),
        GROUP_MEMBERS_MANIFEST,
        resource="group_members",
    )

    assert len(df) == 1
    assert df.loc[0, "group_id"] == "group-1"  # injected _group_id
    assert df.loc[0, "profile_login"] == "alice@example.com"
    assert df.loc[0, "status"] == "ACTIVE"


def test_user_factors_page() -> None:
    df = parse(
        _load("user_factors_page.json"), USER_FACTORS_MANIFEST, resource="user_factors"
    )

    assert len(df) == 2
    assert df.loc[0, "user_id"] == "user-1"  # injected _user_id
    assert df.loc[0, "factor_type"] == "push"
    assert df.loc[1, "profile_phone_number"] == "+1 XXX-XXX-1234"
    assert pd.isna(df.loc[0, "profile_phone_number"])  # absent for push factor


def test_user_roles_page() -> None:
    df = parse(
        _load("user_roles_page.json"), USER_ROLES_MANIFEST, resource="user_roles"
    )

    assert len(df) == 1
    assert df.loc[0, "user_id"] == "user-1"  # injected _user_id
    assert df.loc[0, "type"] == "ORG_ADMIN"
    assert df.loc[0, "assignment_type"] == "USER"
