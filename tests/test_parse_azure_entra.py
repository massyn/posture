import json
from pathlib import Path

import pandas as pd

from posture.collectors.azure_entra import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "azure_entra"

USERS_MANIFEST = MANIFEST["users"]
SIGNINS_MANIFEST = MANIFEST["signins"]
AUDIT_LOGS_MANIFEST = MANIFEST["audit_logs"]


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_users_page() -> None:
    df = parse(_load("users_page.json"), USERS_MANIFEST, resource="users")

    assert len(df) == 2
    assert df.loc[0, "user_id"] == "user-1"
    assert df.loc[0, "job_title"] == "Engineer"
    assert bool(df.loc[0, "account_enabled"]) is True
    assert bool(df.loc[1, "account_enabled"]) is False
    assert json.loads(df.loc[0, "business_phones"]) == ["555-0101"]
    assert df["created_date_time"].dtype == "datetime64[ns, UTC]"
    assert pd.isna(df.loc[1, "created_date_time"])  # absent in fixture


def test_signins_page() -> None:
    df = parse(_load("signins_page.json"), SIGNINS_MANIFEST, resource="signins")

    assert len(df) == 2
    assert list(df["user_principal_name"]) == [
        "alice@example.com",
        "bob@example.com",
    ]
    assert df["created_date_time"].dtype == "datetime64[ns, UTC]"


def test_audit_logs_page() -> None:
    df = parse(
        _load("audit_logs_page.json"), AUDIT_LOGS_MANIFEST, resource="audit_logs"
    )

    assert len(df) == 2
    assert df.loc[0, "user_principal_name"] == "alice@example.com"
    assert df.loc[0, "initiated_by_user"] == "admin@example.com"
    assert pd.isna(df.loc[0, "initiated_by_app"])
    assert df.loc[1, "initiated_by_app"] == "Automation App"
    assert pd.isna(df.loc[1, "initiated_by_user"])
