import json
from pathlib import Path

import pandas as pd

from posture.collectors.okta import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "okta"

USERS_MANIFEST = MANIFEST["users"]
DEVICES_MANIFEST = MANIFEST["devices"]
DEVICE_USERS_MANIFEST = MANIFEST["device_users"]


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_users_page() -> None:
    df = parse(_load("users_page.json"), USERS_MANIFEST, resource="users")

    assert len(df) == 2
    assert df.loc[0, "profile_login"] == "alice@example.com"
    assert df.loc[0, "profile_department"] == "Engineering"
    assert df.loc[0, "type_id"] == "type-1"
    assert df["created"].dtype == "datetime64[ns, UTC]"
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
    assert df["user_created"].dtype == "datetime64[ns, UTC]"
