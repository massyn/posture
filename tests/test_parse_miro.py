import json
from pathlib import Path

import pandas as pd

from posture.collectors.miro import MANIFEST, _to_miro_datetime
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "miro"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def test_boards_flatten_sharing_and_permission_policy() -> None:
    df = parse(_load("boards_page.json")["data"], MANIFEST["boards"], resource="boards")

    assert list(df["name"]) == ["CCM", "public-roadmap"]
    assert df.loc[0, "sharing_access"] == "private"
    assert df.loc[0, "sharing_organization_access"] == "private"
    assert bool(df.loc[0, "sharing_password_required"]) is False
    # the widely-shared board
    assert df.loc[1, "sharing_access"] == "view"
    assert df.loc[1, "sharing_organization_access"] == "comment"
    assert df.loc[1, "perm_sharing_access"] == "anyone"
    assert df.loc[1, "project_id"] == "proj_123"
    assert pd.isna(df.loc[0, "project_id"])
    assert df["created_at"].dtype == "datetime64[us, UTC]"
    assert df.loc[0, "team_id"] == "3458764531002529096"


def test_board_members_grain_with_injected_board_context() -> None:
    raw = _load("board_members_page.json")["data"]
    for record in raw:
        record["_board_id"] = "uXjVL8UdkRI="
        record["_board_name"] = "CCM"
    df = parse(raw, MANIFEST["board_members"], resource="board_members")

    assert list(df["role"]) == ["owner", "commenter"]
    assert set(df["board_name"]) == {"CCM"}


def test_org_members_dormant_and_external_signals() -> None:
    df = parse(
        _load("org_members_page.json")["data"],
        MANIFEST["org_members"],
        resource="org_members",
    )

    assert df.loc[0, "role"] == "organization_internal_admin"
    assert bool(df.loc[1, "active"]) is False
    assert df.loc[1, "license"] == "free_restricted"
    assert json.loads(df.loc[0, "admin_roles"]) == ["COMPANY_ADMIN"]
    assert df["last_activity_at"].dtype == "datetime64[us, UTC]"


def test_teams_and_team_members() -> None:
    teams = parse(_load("teams_page.json")["data"], MANIFEST["teams"], resource="teams")
    assert list(teams["name"]) == ["Cloud", "Design"]

    raw = _load("team_members_page.json")["data"]
    for record in raw:
        record["_team_id"] = "3458764531002529096"
    tm = parse(raw, MANIFEST["team_members"], resource="team_members")
    assert list(tm["role"]) == ["admin", "member"]
    assert list(tm["team_id"]) == ["3458764531002529096", "3458764531002529096"]


def test_audit_logs_flatten_actor_and_context() -> None:
    df = parse(
        _load("audit_logs_page.json")["data"],
        MANIFEST["audit_logs"],
        resource="audit_logs",
    )

    assert list(df["event"]) == ["board_shared", "user_login"]
    assert df.loc[0, "created_by_email"] == "phil.massyn@icloud.com"
    assert df.loc[0, "object_id"] == "uXjVKr2ggek="
    assert df.loc[0, "context_ip"] == "203.0.113.9"
    assert json.loads(df.loc[0, "details"]) == {"newAccess": "view"}
    assert df["created_at"].dtype == "datetime64[us, UTC]"


def test_board_classification_label() -> None:
    record = _load("board_classification_ccm.json")
    record["_board_id"] = "uXjVL8UdkRI="
    record["_board_name"] = "CCM"
    df = parse(
        [record], MANIFEST["board_classifications"], resource="board_classifications"
    )

    assert len(df) == 1
    assert df.loc[0, "label_name"] == "internal"
    assert df.loc[0, "sharing_recommendation"] == "ONLY_WITHIN_ORGANIZATION"
    assert df.loc[0, "board_name"] == "CCM"


def test_to_miro_datetime() -> None:
    assert _to_miro_datetime("2026-01-01T00:00:00Z") == "2026-01-01T00:00:00.000Z"
    assert _to_miro_datetime(1767225600) == "2026-01-01T00:00:00.000Z"
    assert _to_miro_datetime("1767225600") == "2026-01-01T00:00:00.000Z"
