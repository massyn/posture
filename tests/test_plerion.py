import responses

from posture import CCM

_CONFIG = {"endpoint": "au.api.plerion.com", "api_key": "secret-key"}


@responses.activate
def test_findings_cursor_pagination() -> None:
    responses.add(
        responses.GET,
        "https://au.api.plerion.com/v1/tenant/findings",
        json={
            "data": [{"id": "finding-1"}],
            "meta": {"cursor": "next-cursor", "hasNextPage": True},
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "https://au.api.plerion.com/v1/tenant/findings",
        json={"data": [{"id": "finding-2"}], "meta": {"hasNextPage": False}},
        status=200,
    )

    ccm = CCM("plerion", _CONFIG)
    df = ccm.collect("findings")

    assert len(df) == 2
    assert list(df["id"]) == ["finding-1", "finding-2"]
    assert ccm.report("findings")["pages"] == 2

    second_call_params = responses.calls[1].request.params
    assert second_call_params["cursor"] == "next-cursor"


@responses.activate
def test_assets_page_number_pagination_stops_on_no_next_page() -> None:
    responses.add(
        responses.GET,
        "https://au.api.plerion.com/v1/tenant/assets",
        json={
            "data": [{"id": "asset-1"}],
            "meta": {"page": 1, "hasNextPage": True},
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "https://au.api.plerion.com/v1/tenant/assets",
        json={
            "data": [{"id": "asset-2"}],
            "meta": {"page": 2, "hasNextPage": False},
        },
        status=200,
    )

    ccm = CCM("plerion", _CONFIG)
    df = ccm.collect("assets")

    assert len(df) == 2
    assert list(df["id"]) == ["asset-1", "asset-2"]

    second_call_params = responses.calls[1].request.params
    assert second_call_params["page"] == "2"


@responses.activate
def test_authorization_header_uses_bearer_api_key() -> None:
    responses.add(
        responses.GET,
        "https://au.api.plerion.com/v1/tenant/vulnerabilities",
        json={"data": [], "meta": {"hasNextPage": False}},
        status=200,
    )

    ccm = CCM("plerion", _CONFIG)
    ccm.collect("vulnerabilities")

    assert responses.calls[0].request.headers["Authorization"] == "Bearer secret-key"
