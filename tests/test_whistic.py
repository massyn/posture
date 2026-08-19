import json
from urllib.parse import parse_qs, urlparse

import responses

from posture import CCM


@responses.activate
def test_vendors_pagination_stops_when_no_next_link() -> None:
    responses.add(
        responses.GET,
        "https://public.whistic.com/api/vendors",
        json={
            "_links": {"self": {"href": "https://public.whistic.com/api/vendors"}},
            "_embedded": {"vendors": [{"identifier": "v1", "name": "Acme"}]},
        },
        status=200,
    )

    ccm = CCM("whistic", {"token": "token"})
    df = ccm.collect("vendors")

    assert len(df) == 1
    assert ccm.report("vendors")["pages"] == 1


@responses.activate
def test_vendors_follows_next_link_cursor() -> None:
    def callback(request):
        params = parse_qs(urlparse(request.url).query)
        if "cursor" not in params:
            vendors = [{"identifier": f"v{i}", "name": f"Vendor {i}"} for i in range(100)]
            body = {
                "_links": {
                    "next": {
                        "href": "https://public.whistic.com/api/vendors"
                        "?page_size=100&cursor=1700000000000%2Cv99"
                    }
                },
                "_embedded": {"vendors": vendors},
            }
        else:
            assert params["cursor"] == ["1700000000000,v99"]
            body = {
                "_links": {},
                "_embedded": {"vendors": [{"identifier": "v100", "name": "Last Vendor"}]},
            }
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
        json={
            "_links": {},
            "_embedded": {"vendors": [{"identifier": "v1"}, {"identifier": "v2"}]},
        },
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
        json={"_links": {}, "_embedded": {"vendors": []}},
        status=200,
    )

    ccm = CCM("whistic", {"token": "token"})
    df = ccm.collect("vendor_details")

    assert len(df) == 0


@responses.activate
def test_assessments_pagination_stops_on_empty_page() -> None:
    def callback(request):
        params = parse_qs(urlparse(request.url).query)
        if "page_num" not in params:
            body = {
                "_links": {
                    "next": {
                        "href": "https://public.whistic.com/api/assessments"
                        "?page_size=100&page_num=1"
                    }
                },
                "_embedded": {
                    "assessments": [
                        {
                            "identifier": "a1",
                            "vendor_identifier": "v1",
                            "status": "PENDING",
                        }
                    ]
                },
            }
        else:
            # _links.next stays present on an empty page — the real API's
            # quirk this collector has to work around.
            body = {
                "_links": {
                    "next": {
                        "href": "https://public.whistic.com/api/assessments"
                        "?page_size=100&page_num=2"
                    }
                },
                "_embedded": {"assessments": []},
            }
        return (200, {}, json.dumps(body))

    responses.add_callback(
        responses.GET,
        "https://public.whistic.com/api/assessments",
        callback=callback,
        content_type="application/json",
    )

    ccm = CCM("whistic", {"token": "token"})
    df = ccm.collect("assessments")

    assert len(df) == 1
    assert df.loc[0, "identifier"] == "a1"
    # the trailing empty page is still fetched and counted, since presence
    # of _links.next isn't a reliable stop signal for this endpoint
    assert ccm.report("assessments")["pages"] == 2


@responses.activate
def test_custom_endpoint_is_normalized() -> None:
    responses.add(
        responses.GET,
        "https://whistic.internal.example.com/api/vendors",
        json={"_links": {}, "_embedded": {"vendors": []}},
        status=200,
    )

    ccm = CCM(
        "whistic", {"token": "token", "endpoint": "whistic.internal.example.com/api"}
    )
    df = ccm.collect("vendors")

    assert len(df) == 0
