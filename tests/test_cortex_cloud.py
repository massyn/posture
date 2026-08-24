import json

import pytest
import responses

from posture import CCM
from posture.collectors.cortex_cloud import _nest_dotted_keys
from posture.exceptions import PostureError

_CONFIG = {
    "token": "secret-key",
    "api_key_id": "15",
    "endpoint": "https://api-example.xdr.au.paloaltonetworks.com",
}


def test_nest_dotted_keys_builds_a_traversable_nested_dict() -> None:
    flat = {
        "xdm.asset.id": "asset-1",
        "xdm.asset.related_issues.issues_breakdown": {"critical": 2},
        "id": "unrelated-flat-key",
    }

    nested = _nest_dotted_keys(flat)

    assert nested["xdm"]["asset"]["id"] == "asset-1"
    assert nested["xdm"]["asset"]["related_issues"]["issues_breakdown"] == {
        "critical": 2
    }
    assert nested["id"] == "unrelated-flat-key"


@responses.activate
def test_assets_pagination_stops_on_short_page() -> None:
    responses.add(
        responses.POST,
        "https://api-example.xdr.au.paloaltonetworks.com/public_api/v1/assets",
        json={
            "reply": {
                "data": [{"xdm.asset.id": "asset-1", "xdm.asset.name": "web-1"}],
                "metadata": {"filter_count": 1, "total_count": 1},
            }
        },
        status=200,
    )

    ccm = CCM("cortex_cloud", _CONFIG)
    df = ccm.collect("assets")

    assert len(df) == 1
    assert df.loc[0, "id"] == "asset-1"
    assert df.loc[0, "name"] == "web-1"
    assert ccm.report("assets")["pages"] == 1


@responses.activate
def test_assets_follows_search_to_as_next_cursor() -> None:
    def callback(request):
        body = json.loads(request.body)
        search_from = body["request_data"]["search_from"]
        if search_from == 0:
            data = [{"xdm.asset.id": f"a{i}"} for i in range(1000)]
        else:
            assert search_from == 1000
            data = [{"xdm.asset.id": "a1000"}]
        return (200, {}, json.dumps({"reply": {"data": data}}))

    responses.add_callback(
        responses.POST,
        "https://api-example.xdr.au.paloaltonetworks.com/public_api/v1/assets",
        callback=callback,
        content_type="application/json",
    )

    ccm = CCM("cortex_cloud", _CONFIG)
    df = ccm.collect("assets")

    assert len(df) == 1001
    assert ccm.report("assets")["pages"] == 2


@responses.activate
def test_issues_uses_uppercase_envelope_keys_and_nests_dotted_fields() -> None:
    responses.add(
        responses.POST,
        "https://api-example.xdr.au.paloaltonetworks.com/public_api/v1/issue/search",
        json={
            "reply": {
                "DATA": [{"id": 1, "detection.method": "CAS_SECRET_SCANNER"}],
                "TOTAL_COUNT": 1,
                "FILTER_COUNT": 1,
            }
        },
        status=200,
    )

    ccm = CCM("cortex_cloud", _CONFIG)
    df = ccm.collect("issues")

    assert len(df) == 1
    assert df.loc[0, "detection_method"] == "CAS_SECRET_SCANNER"
    assert ccm.report("issues")["pages"] == 1


@responses.activate
def test_issues_follows_search_to_as_next_cursor() -> None:
    def callback(request):
        body = json.loads(request.body)
        search_from = body["request_data"]["search_from"]
        if search_from == 0:
            data = [{"id": i} for i in range(100)]
        else:
            assert search_from == 100
            data = [{"id": 100}]
        return (200, {}, json.dumps({"reply": {"DATA": data}}))

    responses.add_callback(
        responses.POST,
        "https://api-example.xdr.au.paloaltonetworks.com/public_api/v1/issue/search",
        callback=callback,
        content_type="application/json",
    )

    ccm = CCM("cortex_cloud", _CONFIG)
    df = ccm.collect("issues")

    assert len(df) == 101
    assert ccm.report("issues")["pages"] == 2


@responses.activate
def test_auth_headers_sent_on_every_request() -> None:
    responses.add(
        responses.POST,
        "https://api-example.xdr.au.paloaltonetworks.com/public_api/v1/assets",
        json={"reply": {"data": []}},
        status=200,
    )

    ccm = CCM("cortex_cloud", _CONFIG)
    ccm.collect("assets")

    sent = responses.calls[0].request
    assert sent.headers["Authorization"] == "secret-key"
    assert sent.headers["x-xdr-auth-id"] == "15"


@responses.activate
def test_unauthorized_raises_on_401() -> None:
    responses.add(
        responses.POST,
        "https://api-example.xdr.au.paloaltonetworks.com/public_api/v1/assets",
        json={"reply": {"err_code": 401, "err_msg": "Unauthorized"}},
        status=401,
    )

    ccm = CCM("cortex_cloud", _CONFIG)
    with pytest.raises(PostureError, match="assets"):
        ccm.collect("assets")
