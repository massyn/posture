import json
import re
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
import responses

from posture import CCM
from posture.exceptions import IncompleteCollection

FIXTURES = Path(__file__).parent / "fixtures" / "miro"
BASE = "https://api.miro.com"
ORG = "3458764558980462983"


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def _add_context() -> None:
    responses.add(
        responses.GET, f"{BASE}/v1/oauth-token", json=_fixture("oauth_token.json")
    )


def _ccm() -> "CCM":
    return CCM("miro", {"access_token": "tok"})


@responses.activate
def test_boards_offset_pagination_and_policy_flattening() -> None:
    _add_context()
    responses.add(responses.GET, f"{BASE}/v2/boards", json=_fixture("boards_page.json"))

    df = _ccm().collect("boards")

    assert list(df["name"]) == ["CCM", "public-roadmap"]
    assert df.loc[1, "sharing_access"] == "view"
    assert df.loc[1, "sharing_organization_access"] == "comment"
    auth = responses.calls[0].request.headers["Authorization"]
    assert auth == "Bearer tok"


@responses.activate
def test_board_members_fan_out_injects_board_context() -> None:
    _add_context()
    responses.add(responses.GET, f"{BASE}/v2/boards", json=_fixture("boards_page.json"))
    responses.add(
        responses.GET,
        re.compile(rf"{re.escape(BASE)}/v2/boards/[^/]+/members.*"),
        json=_fixture("board_members_page.json"),
    )

    df = _ccm().collect("board_members")

    # 2 boards x 2 members each
    assert len(df) == 4
    assert set(df["board_name"]) == {"CCM", "public-roadmap"}
    assert set(df["role"]) == {"owner", "commenter"}


@responses.activate
def test_org_members_cursor_pagination_uses_discovered_org_id() -> None:
    _add_context()
    responses.add(
        responses.GET,
        f"{BASE}/v2/orgs/{ORG}/members",
        json=_fixture("org_members_page.json"),
    )

    df = _ccm().collect("org_members")

    assert list(df["active"]) == [True, False]
    assert list(df["role"]) == [
        "organization_internal_admin",
        "organization_external_user",
    ]


@responses.activate
def test_teams_and_team_members_fan_out() -> None:
    _add_context()
    responses.add(
        responses.GET, f"{BASE}/v2/orgs/{ORG}/teams", json=_fixture("teams_page.json")
    )
    responses.add(
        responses.GET,
        re.compile(rf"{re.escape(BASE)}/v2/orgs/{ORG}/teams/[^/]+/members.*"),
        json=_fixture("team_members_page.json"),
    )

    df = _ccm().collect("team_members")

    assert len(df) == 4  # 2 teams x 2 members
    assert set(df["role"]) == {"admin", "member"}


@responses.activate
def test_audit_logs_default_window_is_30_days() -> None:
    _add_context()
    responses.add(
        responses.GET, f"{BASE}/v2/audit/logs", json=_fixture("audit_logs_page.json")
    )

    df = _ccm().collect("audit_logs")

    assert list(df["event"]) == ["board_shared", "user_login"]
    qs = parse_qs(urlparse(responses.calls[-1].request.url).query)
    after = qs["createdAfter"][0]
    before = qs["createdBefore"][0]
    assert after.endswith(".000Z") and before.endswith(".000Z")
    # ~30 days apart
    from datetime import datetime

    delta = datetime.fromisoformat(
        before.replace("Z", "+00:00")
    ) - datetime.fromisoformat(after.replace("Z", "+00:00"))
    assert 29 * 24 * 3600 < delta.total_seconds() < 31 * 24 * 3600


@responses.activate
def test_audit_logs_created_after_passthrough() -> None:
    _add_context()
    responses.add(
        responses.GET, f"{BASE}/v2/audit/logs", json=_fixture("audit_logs_page.json")
    )

    _ccm().collect("audit_logs", created_after="2026-01-01T00:00:00Z")

    qs = parse_qs(urlparse(responses.calls[-1].request.url).query)
    assert qs["createdAfter"] == ["2026-01-01T00:00:00.000Z"]


@responses.activate
def test_audit_logs_rejects_conflicting_window_kwargs() -> None:
    _add_context()
    responses.add(
        responses.GET, f"{BASE}/v2/audit/logs", json=_fixture("audit_logs_page.json")
    )

    with pytest.raises((ValueError, IncompleteCollection)):
        _ccm().collect(
            "audit_logs", window_hours=24, created_after="2026-01-01T00:00:00Z"
        )


@responses.activate
def test_board_classifications_skip_unlabelled_board_on_404() -> None:
    _add_context()
    responses.add(responses.GET, f"{BASE}/v2/boards", json=_fixture("boards_page.json"))
    # first board classified, second 404s (no label)
    responses.add(
        responses.GET,
        f"{BASE}/v2/orgs/{ORG}/teams/3458764531002529096/boards/uXjVL8UdkRI=/data-classification",
        json=_fixture("board_classification_ccm.json"),
    )
    responses.add(
        responses.GET,
        f"{BASE}/v2/orgs/{ORG}/teams/3458764531002529096/boards/uXjVKr2ggek=/data-classification",
        json={"status": 404, "code": "notFound"},
        status=404,
    )

    df = _ccm().collect("board_classifications")

    assert len(df) == 1
    assert df.loc[0, "label_name"] == "internal"
    assert df.loc[0, "board_name"] == "CCM"


@responses.activate
def test_missing_scope_403_raises_incomplete_collection() -> None:
    _add_context()
    responses.add(
        responses.GET,
        f"{BASE}/v2/orgs/{ORG}/members",
        json={
            "status": 403,
            "code": "insufficientPermissions",
            "message": "Required scopes: organizations:read",
        },
        status=403,
    )

    with pytest.raises(IncompleteCollection):
        _ccm().collect("org_members")
