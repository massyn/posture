import json
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

import pytest
import responses

from posture import CCM
from posture.collectors.qualys.errors import CredentialsRejected
from posture.exceptions import AuthenticationError, IncompleteCollection

GATEWAY = "https://gateway.qg1.apps.qualys.com"
AUTH_URL = GATEWAY + "/auth"
IMAGES_URL = GATEWAY + "/csapi/v1.3/images/list"
CONTAINERS_URL = GATEWAY + "/csapi/v1.3/containers/list"
REGISTRY_URL = GATEWAY + "/csapi/v1.3/registry"
CONFIG = {
    "username": "u",
    "password": "p",
    "base_url": "qualysapi.qg1.apps.qualys.com",
}

_ZERO_COUNTS = {f"severity{n}Count": 0 for n in range(1, 6)}

VULNERABLE_IMAGE = {
    "sha": "sha-a",
    "imageId": "img-a",
    "uuid": "uuid-a",
    "size": 1024,
    "created": "1767225600000",
    "updated": "1767312000000",
    "repo": [
        {"registry": "docker.io", "repository": "org/app", "tag": "1.0"},
        {"registry": "docker.io", "repository": "org/app", "tag": "latest"},
    ],
    "vulnerabilities": {**_ZERO_COUNTS, "severity5Count": 2},
}
CLEAN_IMAGE = {"sha": "sha-b", "imageId": "img-b", "vulnerabilities": _ZERO_COUNTS}


def _query(call: responses.Call) -> dict:
    return {k: v[0] for k, v in parse_qs(urlparse(call.request.url).query).items()}


def _add_auth() -> None:
    responses.add(responses.POST, AUTH_URL, body="jwt-token", status=201)


@responses.activate
def test_images_follow_link_header_and_explode_repos() -> None:
    _add_auth()
    next_url = IMAGES_URL + "?limit=250&searchAfter=abc"
    responses.add(
        responses.GET,
        IMAGES_URL,
        json={"data": [VULNERABLE_IMAGE]},
        headers={"Link": f'<{next_url}>;rel="next"'},
        match=[responses.matchers.query_param_matcher({"limit": "250"})],
    )
    responses.add(
        responses.GET,
        IMAGES_URL,
        json={"data": [CLEAN_IMAGE]},
        match=[
            responses.matchers.query_param_matcher(
                {"limit": "250", "searchAfter": "abc"}
            )
        ],
    )

    ccm = CCM("qualys", CONFIG)
    images = ccm.collect("container_images")
    repos = ccm.collect("container_image_repos")

    assert list(images["image_sha"]) == ["sha-a", "sha-b"]
    assert images.loc[0, "created"].isoformat() == "2026-01-01T00:00:00+00:00"
    assert images.loc[0, "severity5_count"] == 2
    assert images.loc[0, "size"] == 1024
    assert list(repos["tag"]) == ["1.0", "latest"]
    assert set(repos["image_sha"]) == {"sha-a"}
    assert ccm.report("container_images")["pages"] == 2
    assert responses.calls[1].request.headers["Authorization"] == "Bearer jwt-token"
    assert len(responses.calls) == 3  # repos replayed from cache


@responses.activate
def test_image_vulnerabilities_fan_out_only_over_vulnerable_images() -> None:
    _add_auth()
    responses.add(
        responses.GET, IMAGES_URL, json={"data": [VULNERABLE_IMAGE, CLEAN_IMAGE]}
    )
    responses.add(
        responses.GET,
        GATEWAY + "/csapi/v1.3/images/sha-a",
        json={
            "sha": "sha-a",
            "imageId": "img-a",
            "vulnerabilities": [
                {
                    "qid": 376157,
                    "title": "OpenSSL RCE",
                    "severity": 5,
                    "cveids": ["CVE-2024-0001"],
                    "patchAvailable": True,
                    "software": [
                        {"name": "openssl", "version": "3.0.2", "fixVersion": "3.0.3"}
                    ],
                    "firstFound": "1767225600000",
                }
            ],
        },
    )

    ccm = CCM("qualys", CONFIG)
    vulns = ccm.collect("container_image_vulnerabilities")
    images = ccm.collect("container_images")

    assert len(vulns) == 1
    row = vulns.iloc[0]
    assert row["image_sha"] == "sha-a"
    assert row["image_id"] == "img-a"
    assert row["qid"] == "376157"
    assert json.loads(row["cve_ids"]) == ["CVE-2024-0001"]
    assert json.loads(row["software"])[0]["fixVersion"] == "3.0.3"
    assert row["first_found"].isoformat() == "2026-01-01T00:00:00+00:00"
    assert len(images) == 2
    detail_calls = [c for c in responses.calls if "/images/sha-" in c.request.url]
    assert len(detail_calls) == 1  # sha-b has no findings
    list_calls = [c for c in responses.calls if c.request.url.startswith(IMAGES_URL)]
    assert len(list_calls) == 1  # container_images reused from cache


@responses.activate
def test_image_removed_before_detail_call_is_skipped() -> None:
    _add_auth()
    responses.add(responses.GET, IMAGES_URL, json={"data": [VULNERABLE_IMAGE]})
    responses.add(responses.GET, GATEWAY + "/csapi/v1.3/images/sha-a", status=404)

    vulns = CCM("qualys", CONFIG).collect("container_image_vulnerabilities")

    assert len(vulns) == 0


@responses.activate
def test_containers_pass_filter_through() -> None:
    _add_auth()
    responses.add(
        responses.GET,
        CONTAINERS_URL,
        json={
            "data": [
                {
                    "containerId": "c-1",
                    "sha": "csha-1",
                    "name": "web",
                    "state": "RUNNING",
                    "isRoot": True,
                    "stateChanged": "1767225600000",
                    "host": {"hostname": "node-1"},
                }
            ]
        },
    )

    df = CCM("qualys", CONFIG).collect("containers", filter="state:RUNNING")

    assert _query(responses.calls[1]) == {"limit": "250", "filter": "state:RUNNING"}
    assert df.loc[0, "container_id"] == "c-1"
    assert bool(df.loc[0, "is_root"]) is True
    assert json.loads(df.loc[0, "host"]) == {"hostname": "node-1"}
    assert df.loc[0, "state_changed"].isoformat() == "2026-01-01T00:00:00+00:00"


@responses.activate
def test_registries_page_until_count_reached() -> None:
    _add_auth()
    first = [{"registryUuid": f"r-{n}"} for n in range(50)]
    responses.add(responses.GET, REGISTRY_URL, json={"count": 51, "data": first})
    responses.add(
        responses.GET,
        REGISTRY_URL,
        json={"count": 51, "data": [{"registryUuid": "r-50", "repoCount": 3}]},
    )

    df = CCM("qualys", CONFIG).collect("container_registries")

    assert len(df) == 51
    assert df.iloc[-1]["repo_count"] == 3
    pages = [_query(c) for c in responses.calls[1:]]
    assert pages == [
        {"pageNumber": "1", "pageSize": "50"},
        {"pageNumber": "2", "pageSize": "50"},
    ]


@responses.activate
def test_expired_token_is_refreshed_on_401() -> None:
    responses.add(responses.POST, AUTH_URL, body="old-token", status=201)
    responses.add(responses.POST, AUTH_URL, body="new-token", status=201)
    responses.add(responses.GET, CONTAINERS_URL, json={"data": []})
    responses.add(responses.GET, CONTAINERS_URL, status=401)
    responses.add(responses.GET, CONTAINERS_URL, json={"data": []})

    ccm = CCM("qualys", CONFIG)
    ccm.collect("containers")
    gateway = ccm._routes["containers"]._gateway
    # Age the token so the 401 reads as expiry, not a refusal.
    gateway.token_issued_at -= timedelta(hours=1)
    df = ccm.collect("containers", filter="state:RUNNING")

    assert len(df) == 0
    gets = [c for c in responses.calls if c.request.method == "GET"]
    assert gets[-1].request.headers["Authorization"] == "Bearer new-token"


@responses.activate
def test_401_with_fresh_token_fails_as_no_module_access() -> None:
    _add_auth()
    responses.add(responses.GET, CONTAINERS_URL, status=401, body="Unauthorized")

    ccm = CCM("qualys", CONFIG)
    with pytest.raises(IncompleteCollection, match="just issued") as excinfo:
        ccm.collect("containers")

    cause = excinfo.value.__cause__
    assert isinstance(cause, AuthenticationError)
    assert not isinstance(cause, CredentialsRejected)
    assert "gateway.qg1.apps.qualys.com" in str(cause)
    assert "Community Edition" in cause.hint
    auth_calls = [c for c in responses.calls if c.request.url == AUTH_URL]
    assert len(auth_calls) == 1


@responses.activate
def test_server_error_keeps_host_and_qualys_text() -> None:
    _add_auth()
    responses.add(
        responses.POST,
        GATEWAY + "/rest/2.0/search/am/asset",
        status=500,
        body='{"errorMessage": "module not enabled"}',
    )

    ccm = CCM("qualys", CONFIG)
    with pytest.raises(IncompleteCollection, match="module not enabled") as excinfo:
        ccm.collect("assets")

    assert "gateway.qg1.apps.qualys.com returned HTTP 500" in str(excinfo.value)


@responses.activate
def test_gateway_login_is_shared_with_csam() -> None:
    _add_auth()
    responses.add(responses.GET, CONTAINERS_URL, json={"data": []})
    responses.add(
        responses.POST,
        GATEWAY + "/rest/2.0/search/am/asset",
        json={"responseCode": "SUCCESS", "hasMore": 0, "assetListData": {}},
    )

    ccm = CCM("qualys", CONFIG)
    ccm.collect("containers")
    ccm.collect("assets")

    auth_calls = [c for c in responses.calls if c.request.url == AUTH_URL]
    assert len(auth_calls) == 1


def test_registries_reject_kwargs() -> None:
    ccm = CCM("qualys", CONFIG)
    with pytest.raises(IncompleteCollection, match="Unsupported kwargs"):
        ccm.collect("container_registries", filter="x")
