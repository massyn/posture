import io
import json

import pytest
import requests
import responses

from posture import CCM
from posture.collectors import cortex_cloud
from posture.collectors.cortex_cloud import _nest_dotted_keys
from posture.exceptions import IncompleteCollection, PostureError

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


_SNAPSHOT_URL = (
    "https://api-example.xdr.au.paloaltonetworks.com"
    "/vulnerability-management/v1/vulnerability-finding/snapshot"
)


def _ndjson(records: list[dict]) -> str:
    return "".join(json.dumps(r) + "\n" for r in records)


@responses.activate
def test_vulnerabilities_streams_ndjson_in_bounded_batches(monkeypatch) -> None:
    monkeypatch.setattr(cortex_cloud, "_SNAPSHOT_BATCH_SIZE", 2)
    responses.add(
        responses.POST,
        _SNAPSHOT_URL,
        body=_ndjson([{"platform_id": f"vf-{i}", "cve_id": "CVE-1"} for i in range(5)])
        + "\n",  # trailing blank line must be skipped, not parsed
        status=200,
        content_type="application/x-ndjson",
    )

    ccm = CCM("cortex_cloud", _CONFIG)
    pages = list(ccm.collect_page("vulnerabilities", filter={"AND": []}))

    assert [len(p) for p in pages] == [2, 2, 1]
    assert pages[2].loc[0, "platform_id"] == "vf-4"
    assert len(responses.calls) == 1  # one snapshot request, read across pages
    sent = json.loads(responses.calls[0].request.body)
    assert sent == {"request_data": {"filter": {"AND": []}}}


@responses.activate
def test_vulnerabilities_record_limit_is_sent_as_server_side_limit() -> None:
    responses.add(
        responses.POST,
        _SNAPSHOT_URL,
        body=_ndjson([{"platform_id": "vf-0"}]),
        status=200,
        content_type="application/x-ndjson",
    )

    ccm = CCM("cortex_cloud", _CONFIG, record_limit=50)
    ccm.collect("vulnerabilities")

    sent = json.loads(responses.calls[0].request.body)
    assert sent == {"request_data": {"limit": 50}}


@responses.activate
def test_vulnerabilities_accepts_inline_json_list() -> None:
    responses.add(
        responses.POST,
        _SNAPSHOT_URL,
        json=[{"platform_id": "vf-0", "cve_id": "CVE-1"}],
        status=200,
    )

    ccm = CCM("cortex_cloud", _CONFIG)
    df = ccm.collect("vulnerabilities")

    assert len(df) == 1
    assert df.loc[0, "cve_id"] == "CVE-1"


@responses.activate
def test_vulnerabilities_rejects_unrecognised_inline_shape() -> None:
    responses.add(responses.POST, _SNAPSHOT_URL, json={"unexpected": []}, status=200)

    ccm = CCM("cortex_cloud", _CONFIG)
    with pytest.raises(IncompleteCollection, match="unexpected"):
        ccm.collect("vulnerabilities")


@pytest.mark.parametrize("status", [401, 403, 408, 429, 500])
@responses.activate
def test_vulnerabilities_snapshot_request_is_never_retried(status: int) -> None:
    responses.add(
        responses.POST,
        _SNAPSHOT_URL,
        json={"reply": {"err_code": status, "err_msg": "nope"}},
        status=status,
    )

    ccm = CCM("cortex_cloud", _CONFIG)
    with pytest.raises(IncompleteCollection, match=f"HTTP {status}"):
        ccm.collect("vulnerabilities")

    assert len(responses.calls) == 1


@responses.activate
def test_vulnerabilities_connection_error_is_never_retried() -> None:
    responses.add(
        responses.POST,
        _SNAPSHOT_URL,
        body=requests.exceptions.ReadTimeout("read timed out"),
    )

    ccm = CCM("cortex_cloud", _CONFIG)
    with pytest.raises(IncompleteCollection, match="not retried"):
        ccm.collect("vulnerabilities")

    assert len(responses.calls) == 1


def test_vulnerabilities_mid_stream_failure_is_not_retried(monkeypatch) -> None:
    monkeypatch.setattr(cortex_cloud, "_SNAPSHOT_BATCH_SIZE", 1)
    opened = []

    def broken_lines():
        yield json.dumps({"platform_id": "vf-0"}).encode()
        raise requests.exceptions.ChunkedEncodingError("connection reset")

    def fake_open(self, kwargs):
        response = requests.Response()
        response.raw = io.BytesIO()
        response.headers["Content-Type"] = "application/x-ndjson"
        opened.append(response)
        return cortex_cloud._SnapshotStream(response, broken_lines())

    monkeypatch.setattr(cortex_cloud.CortexCloudCollector, "_open_snapshot", fake_open)

    ccm = CCM("cortex_cloud", _CONFIG)
    pages = ccm.collect_page("vulnerabilities")
    assert len(next(pages)) == 1
    with pytest.raises(IncompleteCollection, match="can't be resumed"):
        next(pages)

    assert len(opened) == 1  # the snapshot was never re-requested


@responses.activate
def test_vulnerabilities_snapshot_timeout_config_sets_read_timeout(
    monkeypatch,
) -> None:
    responses.add(
        responses.POST,
        _SNAPSHOT_URL,
        body=_ndjson([{"platform_id": "vf-0"}]),
        status=200,
        content_type="application/x-ndjson",
    )
    sent_timeouts = []
    original_post = requests.Session.post

    def spy_post(self, url, **kwargs):
        sent_timeouts.append(kwargs.get("timeout"))
        return original_post(self, url, **kwargs)

    monkeypatch.setattr(requests.Session, "post", spy_post)

    ccm = CCM("cortex_cloud", {**_CONFIG, "snapshot_timeout": "1800"})
    ccm.collect("vulnerabilities")

    assert sent_timeouts == [(30, 1800.0)]
