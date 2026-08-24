import responses

from posture import CCM


@responses.activate
def test_users_pagination_follows_next_cursor() -> None:
    responses.add(
        responses.GET,
        "https://slack.com/api/admin.users.list",
        json={
            "ok": True,
            "users": [{"id": "U1", "has_2fa": True}],
            "response_metadata": {"next_cursor": "abc"},
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "https://slack.com/api/admin.users.list",
        json={
            "ok": True,
            "users": [{"id": "U2", "has_2fa": False}],
            "response_metadata": {"next_cursor": ""},
        },
        status=200,
    )

    ccm = CCM("slack", {"token": "xoxp-tok"})
    df = ccm.collect("users")

    assert list(df["id"]) == ["U1", "U2"]
    assert list(df["has_2fa"]) == [True, False]
    assert ccm.report("users")["pages"] == 2


@responses.activate
def test_channel_members_fans_out_per_channel_and_injects_channel_id() -> None:
    responses.add(
        responses.GET,
        "https://slack.com/api/admin.conversations.search",
        json={
            "ok": True,
            "conversations": [{"id": "C1"}, {"id": "C2"}],
            "response_metadata": {"next_cursor": ""},
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "https://slack.com/api/conversations.members",
        json={
            "ok": True,
            "members": ["U1", "U2"],
            "response_metadata": {"next_cursor": ""},
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "https://slack.com/api/conversations.members",
        json={"ok": True, "members": [], "response_metadata": {"next_cursor": ""}},
        status=200,
    )

    ccm = CCM("slack", {"token": "xoxp-tok"})
    df = ccm.collect("channel_members")

    assert len(df) == 2
    assert set(df["channel_id"]) <= {"C1", "C2"}
    assert set(df["user_id"]) == {"U1", "U2"}


@responses.activate
def test_missing_scope_fails_immediately_without_retry() -> None:
    from posture.exceptions import IncompleteCollection

    responses.add(
        responses.GET,
        "https://slack.com/api/admin.users.list",
        json={"ok": False, "error": "missing_scope"},
        status=200,
    )

    ccm = CCM("slack", {"token": "xoxb-thin-token"})

    try:
        ccm.collect("users")
        assert False, "expected IncompleteCollection"
    except IncompleteCollection:
        pass

    # Exactly one call — a permanent scope error is not worth retrying.
    assert len(responses.calls) == 1


@responses.activate
def test_invalid_auth_is_retried_then_propagates_as_incomplete_collection(
    monkeypatch,
) -> None:
    from posture.exceptions import IncompleteCollection

    monkeypatch.setattr("posture.base.time.sleep", lambda _seconds: None)

    responses.add(
        responses.GET,
        "https://slack.com/api/admin.users.list",
        json={"ok": False, "error": "invalid_auth"},
        status=200,
    )

    ccm = CCM("slack", {"token": "bad-token"})

    try:
        ccm.collect("users")
        assert False, "expected IncompleteCollection"
    except IncompleteCollection:
        pass


@responses.activate
def test_user_groups_is_not_paginated() -> None:
    responses.add(
        responses.GET,
        "https://slack.com/api/usergroups.list",
        json={
            "ok": True,
            "usergroups": [{"id": "S1", "name": "Team", "date_delete": 0}],
        },
        status=200,
    )

    ccm = CCM("slack", {"token": "xoxp-tok"})
    df = ccm.collect("user_groups")

    assert list(df["id"]) == ["S1"]
    assert df.loc[0, "date_delete"] == 0
    assert ccm.report("user_groups")["pages"] == 1


@responses.activate
def test_apps_flattens_nested_app_and_scopes() -> None:
    responses.add(
        responses.GET,
        "https://slack.com/api/admin.apps.approved.list",
        json={
            "ok": True,
            "approved_apps": [
                {
                    "app": {"id": "A1", "name": "Test App", "is_internal": False},
                    "scopes": [{"name": "bot", "is_sensitive": True}],
                    "date_updated": 1574296707,
                    "last_resolved_by": {"actor_id": "W1", "actor_type": "user"},
                }
            ],
            "response_metadata": {"next_cursor": ""},
        },
        status=200,
    )

    ccm = CCM("slack", {"token": "xoxp-tok"})
    df = ccm.collect("apps")

    assert df.loc[0, "id"] == "A1"
    assert df.loc[0, "name"] == "Test App"
    assert df.loc[0, "last_resolved_by_actor_id"] == "W1"
    assert "bot" in df.loc[0, "scopes"]
