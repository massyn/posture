import responses

from posture import CCM


@responses.activate
def test_agents_pagination_follows_cursor() -> None:
    responses.add(
        responses.GET,
        "https://example.sentinelone.net/web/api/v2.1/agents",
        json={
            "pagination": {"totalItems": 2, "nextCursor": "abc"},
            "data": [{"id": "1", "computerName": "WIN-1"}],
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "https://example.sentinelone.net/web/api/v2.1/agents",
        json={
            "pagination": {"totalItems": 2, "nextCursor": None},
            "data": [{"id": "2", "computerName": "WIN-2"}],
        },
        status=200,
    )

    ccm = CCM(
        "sentinelone",
        {"console_url": "https://example.sentinelone.net", "api_token": "tok"},
    )
    df = ccm.collect("agents")

    assert len(df) == 2
    assert ccm.report("agents")["pages"] == 2
    second_request = responses.calls[-1].request
    assert "cursor=abc" in second_request.url


@responses.activate
def test_threats_page() -> None:
    responses.add(
        responses.GET,
        "https://example.sentinelone.net/web/api/v2.1/threats",
        json={
            "pagination": {"totalItems": 1, "nextCursor": None},
            "data": [
                {
                    "id": "threat-1",
                    "threatInfo": {"classification": "Malware"},
                    "agentRealtimeInfo": {"agentUuid": "uuid-1"},
                }
            ],
        },
        status=200,
    )

    ccm = CCM(
        "sentinelone",
        {"console_url": "https://example.sentinelone.net", "api_token": "tok"},
    )
    df = ccm.collect("threats")

    assert len(df) == 1
    assert df.loc[0, "classification"] == "Malware"


@responses.activate
def test_console_url_normalizes_bare_host() -> None:
    responses.add(
        responses.GET,
        "https://example.sentinelone.net/web/api/v2.1/sites",
        json={"pagination": {"totalItems": 0, "nextCursor": None}, "data": []},
        status=200,
    )

    ccm = CCM(
        "sentinelone",
        {"console_url": "example.sentinelone.net", "api_token": "tok"},
    )
    df = ccm.collect("sites")

    assert len(df) == 0


@responses.activate
def test_authorization_header_uses_apitoken_scheme() -> None:
    responses.add(
        responses.GET,
        "https://example.sentinelone.net/web/api/v2.1/groups",
        json={"pagination": {"totalItems": 0, "nextCursor": None}, "data": []},
        status=200,
    )

    ccm = CCM(
        "sentinelone",
        {"console_url": "https://example.sentinelone.net", "api_token": "tok"},
    )
    ccm.collect("groups")

    request = responses.calls[-1].request
    assert request.headers["Authorization"] == "ApiToken tok"
