import responses

from posture import CCM

_TOKEN_URL = "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token"


def _mock_token() -> None:
    responses.add(
        responses.POST,
        _TOKEN_URL,
        json={"access_token": "tok", "expires_in": 3600},
        status=200,
    )


def _ccm() -> CCM:
    return CCM(
        "teams",
        {"tenant_id": "tenant-1", "client_id": "id", "client_secret": "secret"},
    )


@responses.activate
def test_teams_filters_groups_to_team_provisioned() -> None:
    _mock_token()
    responses.add(
        responses.GET,
        "https://graph.microsoft.com/v1.0/groups",
        json={"value": [{"id": "team-1", "displayName": "Engineering"}]},
        status=200,
    )

    df = _ccm().collect("teams")

    assert list(df["team_id"]) == ["team-1"]
    request = responses.calls[1].request
    assert "resourceProvisioningOptions" in request.url


@responses.activate
def test_team_settings_batches_ids_from_teams() -> None:
    _mock_token()
    responses.add(
        responses.GET,
        "https://graph.microsoft.com/v1.0/groups",
        json={"value": [{"id": "team-1"}]},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://graph.microsoft.com/v1.0/teams/team-1",
        json={
            "isArchived": False,
            "memberSettings": {"allowAddRemoveApps": False},
            "guestSettings": {"allowCreateUpdateChannels": True},
            "summary": {"ownersCount": 2, "membersCount": 5, "guestsCount": 1},
        },
        status=200,
    )

    df = _ccm().collect("team_settings")

    assert len(df) == 1
    assert df.loc[0, "team_id"] == "team-1"
    assert bool(df.loc[0, "member_allow_add_remove_apps"]) is False
    assert df.loc[0, "guests_count"] == 1


@responses.activate
def test_channels_fans_out_per_team_and_follows_next_link() -> None:
    _mock_token()
    responses.add(
        responses.GET,
        "https://graph.microsoft.com/v1.0/groups",
        json={"value": [{"id": "team-1"}]},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://graph.microsoft.com/v1.0/teams/team-1/channels",
        json={
            "value": [{"id": "chan-1", "membershipType": "shared"}],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/teams/team-1/channels?$skiptoken=abc",
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "https://graph.microsoft.com/v1.0/teams/team-1/channels?$skiptoken=abc",
        json={"value": [{"id": "chan-2", "membershipType": "standard"}]},
        status=200,
    )

    df = _ccm().collect("channels")

    assert set(df["channel_id"]) == {"chan-1", "chan-2"}
    assert (df["team_id"] == "team-1").all()


@responses.activate
def test_installed_apps_expands_teams_app_definition() -> None:
    _mock_token()
    responses.add(
        responses.GET,
        "https://graph.microsoft.com/v1.0/groups",
        json={"value": [{"id": "team-1"}]},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://graph.microsoft.com/v1.0/teams/team-1/installedApps",
        json={
            "value": [
                {
                    "id": "install-1",
                    "teamsAppDefinition": {
                        "teamsAppId": "app-1",
                        "displayName": "Some App",
                        "version": "1.0.0",
                    },
                }
            ]
        },
        status=200,
    )

    df = _ccm().collect("installed_apps")

    assert df.loc[0, "teams_app_id"] == "app-1"
    assert df.loc[0, "display_name"] == "Some App"
    request = responses.calls[2].request
    assert "teamsAppDefinition" in request.url


@responses.activate
def test_team_members_reports_roles() -> None:
    _mock_token()
    responses.add(
        responses.GET,
        "https://graph.microsoft.com/v1.0/groups",
        json={"value": [{"id": "team-1"}]},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://graph.microsoft.com/v1.0/teams/team-1/members",
        json={
            "value": [
                {"id": "m1", "roles": ["owner"], "displayName": "Ada", "userId": "u1"}
            ]
        },
        status=200,
    )

    df = _ccm().collect("team_members")

    assert df.loc[0, "user_id"] == "u1"
    assert "owner" in df.loc[0, "roles"]


@responses.activate
def test_team_settings_404_skips_team_without_failing_collection() -> None:
    _mock_token()
    responses.add(
        responses.GET,
        "https://graph.microsoft.com/v1.0/groups",
        json={"value": [{"id": "team-1"}]},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://graph.microsoft.com/v1.0/teams/team-1",
        json={"error": {"code": "NotFound"}},
        status=404,
    )

    df = _ccm().collect("team_settings")

    assert len(df) == 0
