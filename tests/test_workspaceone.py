import responses

from posture import CCM


@responses.activate
def test_computers_pagination_stops_when_fetched_reaches_total() -> None:
    responses.add(
        responses.POST,
        "https://na.uemauth.workspaceone.com/connect/token",
        json={"access_token": "tok"},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://as123.awmdm.com/API/mdm/devices/search",
        json={"devices": [{"Id": {"Value": 1}}], "total": 2},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://as123.awmdm.com/API/mdm/devices/search",
        json={"devices": [{"Id": {"Value": 2}}], "total": 2},
        status=200,
    )

    ccm = CCM(
        "workspaceone",
        {
            "client_id": "id",
            "client_secret": "secret",
            "api_server": "as123.awmdm.com",
            "token_url": "https://na.uemauth.workspaceone.com/connect/token",
        },
    )
    df = ccm.collect("computers")

    assert list(df["device_id"]) == ["1", "2"]
    assert ccm.report("computers")["pages"] == 2


@responses.activate
def test_token_url_defaults_to_apac_when_not_configured(monkeypatch) -> None:
    monkeypatch.delenv("WORKSPACEONE_TOKEN_URL", raising=False)

    responses.add(
        responses.POST,
        "https://apac.uemauth.workspaceone.com/connect/token",
        json={"access_token": "tok"},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://as123.awmdm.com/API/mdm/devices/search",
        json={"devices": [], "total": 0},
        status=200,
    )

    ccm = CCM(
        "workspaceone",
        {"client_id": "id", "client_secret": "secret", "api_server": "as123.awmdm.com"},
    )
    ccm.collect("computers")

    # only way this succeeds: the collector posted to the default APAC token
    # URL registered above, not some unregistered URL responses would 500 on.
    assert len(responses.calls) == 2
