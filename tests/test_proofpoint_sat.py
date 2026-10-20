import json
from urllib.parse import parse_qs, urlsplit

import pytest
import responses

from posture import CCM

_US_USERS = "https://results.us.securityeducation.com/api/reporting/v0.3.0/users"


def _envelope(data, *, page=1, count=None, next_link=None):
    links = {"next": next_link} if next_link else {}
    meta = {"page_number": page, "page_size": 5000}
    if count is not None:
        meta["count"] = count
    return {"data": data, "meta": meta, "links": links}


def _row(i):
    return {"id": str(i), "type": "users", "attributes": {"useremailaddress": f"{i}@x"}}


@responses.activate
def test_sends_api_key_header_and_default_params() -> None:
    responses.add(responses.GET, _US_USERS, json=_envelope([_row(1)]), status=200)

    ccm = CCM("proofpoint_sat", {"token": "secret"})
    df = ccm.collect("users")

    assert len(df) == 1
    request = responses.calls[0].request
    assert request.headers["x-apikey-token"] == "secret"
    params = parse_qs(urlsplit(request.url).query)
    assert params["page[number]"] == ["1"]
    assert params["user_tag_enable"] == ["TRUE"]


@responses.activate
def test_follows_pages_until_meta_count_is_reached() -> None:
    def callback(request):
        params = parse_qs(urlsplit(request.url).query)
        page = int(params["page[number]"][0])
        if page == 1:
            body = _envelope([_row(i) for i in range(5000)], page=1, count=5001)
        else:
            assert page == 2
            body = _envelope([_row(5000)], page=2, count=5001)
        return (200, {}, json.dumps(body))

    responses.add_callback(
        responses.GET, _US_USERS, callback=callback, content_type="application/json"
    )

    ccm = CCM("proofpoint_sat", {"token": "secret"})
    df = ccm.collect("users")

    assert len(df) == 5001
    assert ccm.report("users")["pages"] == 2


@responses.activate
def test_follows_next_link_without_meta_count() -> None:
    def callback(request):
        page = int(parse_qs(urlsplit(request.url).query)["page[number]"][0])
        if page == 1:
            body = _envelope([_row(1)], next_link="/users?page[number]=2")
        else:
            body = _envelope([_row(2)], page=2)
        return (200, {}, json.dumps(body))

    responses.add_callback(
        responses.GET, _US_USERS, callback=callback, content_type="application/json"
    )

    df = CCM("proofpoint_sat", {"token": "secret"}).collect("users")

    assert list(df["id"]) == ["1", "2"]


@responses.activate
def test_kwargs_override_default_params() -> None:
    responses.add(responses.GET, _US_USERS, json=_envelope([]), status=200)

    CCM("proofpoint_sat", {"token": "secret"}).collect(
        "users", user_tag_enable="FALSE", **{"filter[_includedeletedusers]": "TRUE"}
    )

    params = parse_qs(urlsplit(responses.calls[0].request.url).query)
    assert params["user_tag_enable"] == ["FALSE"]
    assert params["filter[_includedeletedusers]"] == ["TRUE"]


@responses.activate
def test_region_selects_host() -> None:
    responses.add(
        responses.GET,
        "https://results.eu.securityeducation.com/api/reporting/v0.3.0/phishing",
        json=_envelope([]),
        status=200,
    )

    df = CCM("proofpoint_sat", {"token": "secret", "region": "EU"}).collect("phishing")

    assert len(df) == 0


def test_unknown_region_fails_at_construction() -> None:
    with pytest.raises(ValueError, match="PROOFPOINT_SAT_REGION"):
        CCM("proofpoint_sat", {"token": "secret", "region": "mars"})
