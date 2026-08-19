import json

import responses

from posture import CCM


@responses.activate
def test_vendors_pagination_stops_on_short_page() -> None:
    responses.add(
        responses.GET,
        "https://public.whistic.com/api/vendors",
        json=[{"identifier": "v1", "name": "Acme"}],
        status=200,
    )

    ccm = CCM("whistic", {"token": "token"})
    df = ccm.collect("vendors")

    assert len(df) == 1
    assert ccm.report("vendors")["pages"] == 1


@responses.activate
def test_vendors_follows_last_identifier_as_next_cursor() -> None:
    def callback(request):
        params = dict(
            pair.split("=") for pair in request.url.split("?", 1)[1].split("&")
        )
        if "cursor" not in params:
            body = [{"identifier": f"v{i}", "name": f"Vendor {i}"} for i in range(100)]
        else:
            assert params["cursor"] == "v99"
            body = [{"identifier": "v100", "name": "Last Vendor"}]
        return (200, {}, json.dumps(body))

    responses.add_callback(
        responses.GET,
        "https://public.whistic.com/api/vendors",
        callback=callback,
        content_type="application/json",
    )

    ccm = CCM("whistic", {"token": "token"})
    df = ccm.collect("vendors")

    assert len(df) == 101
    assert ccm.report("vendors")["pages"] == 2


@responses.activate
def test_vendor_details_fans_out_per_vendor_id() -> None:
    responses.add(
        responses.GET,
        "https://public.whistic.com/api/vendors",
        json=[{"identifier": "v1"}, {"identifier": "v2"}],
        status=200,
    )
    responses.add(
        responses.GET,
        "https://public.whistic.com/api/vendors/v1",
        json={"identifier": "v1", "name": "Acme"},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://public.whistic.com/api/vendors/v2",
        json={"identifier": "v2", "name": "Beta"},
        status=200,
    )

    ccm = CCM("whistic", {"token": "token"})
    df = ccm.collect("vendor_details")

    assert len(df) == 2
    assert set(df["identifier"]) == {"v1", "v2"}


@responses.activate
def test_vendor_details_empty_when_no_vendors() -> None:
    responses.add(
        responses.GET,
        "https://public.whistic.com/api/vendors",
        json=[],
        status=200,
    )

    ccm = CCM("whistic", {"token": "token"})
    df = ccm.collect("vendor_details")

    assert len(df) == 0


@responses.activate
def test_custom_endpoint_is_normalized() -> None:
    responses.add(
        responses.GET,
        "https://whistic.internal.example.com/api/vendors",
        json=[],
        status=200,
    )

    ccm = CCM(
        "whistic", {"token": "token", "endpoint": "whistic.internal.example.com/api"}
    )
    df = ccm.collect("vendors")

    assert len(df) == 0
