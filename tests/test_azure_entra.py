import responses

from posture import CCM


@responses.activate
def test_users_follows_odata_next_link() -> None:
    responses.add(
        responses.POST,
        "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token",
        json={"access_token": "tok"},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://graph.microsoft.com/v1.0/users",
        json={
            "value": [{"id": "user-1"}],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skiptoken=abc",
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "https://graph.microsoft.com/v1.0/users?$skiptoken=abc",
        json={"value": [{"id": "user-2"}]},
        status=200,
    )

    ccm = CCM(
        "azure_entra",
        {"tenant_id": "tenant-1", "client_id": "id", "client_secret": "secret"},
    )
    df = ccm.collect("users")

    assert list(df["user_id"]) == ["user-1", "user-2"]
    assert ccm.report("users")["pages"] == 2


@responses.activate
def test_signins_applies_days_filter() -> None:
    responses.add(
        responses.POST,
        "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token",
        json={"access_token": "tok"},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://graph.microsoft.com/v1.0/auditLogs/signIns",
        json={"value": [{"userPrincipalName": "alice@example.com"}]},
        status=200,
    )

    ccm = CCM(
        "azure_entra",
        {"tenant_id": "tenant-1", "client_id": "id", "client_secret": "secret"},
    )
    df = ccm.collect("signins", days=30)

    assert len(df) == 1
    request = responses.calls[-1].request
    assert "createdDateTime+ge" in request.url or "createdDateTime%20ge" in request.url


@responses.activate
def test_audit_logs_collects() -> None:
    responses.add(
        responses.POST,
        "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token",
        json={"access_token": "tok"},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits",
        json={"value": [{"id": "audit-1", "activityDisplayName": "Add user"}]},
        status=200,
    )

    ccm = CCM(
        "azure_entra",
        {"tenant_id": "tenant-1", "client_id": "id", "client_secret": "secret"},
    )
    df = ccm.collect("audit_logs")

    assert len(df) == 1
    assert df.loc[0, "activity_display_name"] == "Add user"
