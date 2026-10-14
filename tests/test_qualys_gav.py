import json
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

import pytest
import responses

from posture import CCM
from posture.exceptions import AuthenticationError, IncompleteCollection

GATEWAY = "https://gateway.qg1.apps.qualys.com"
AUTH_URL = GATEWAY + "/auth"
SEARCH_URL = GATEWAY + "/rest/2.0/search/am/asset"
CONFIG = {
    "username": "u",
    "password": "p",
    "gateway_url": "gateway.qg1.apps.qualys.com",
}

ASSET = {
    "assetId": 2001,
    "assetUUID": "uuid-1",
    "hostId": 3077710,
    "assetName": "web-01",
    "address": "10.0.0.5",
    "operatingSystem": {"osName": "Ubuntu", "fullName": "Ubuntu 22.04"},
    "criticality": {"score": 3, "isDefault": False},
    "tagList": {"tag": [{"tagId": 1, "tagName": "Prod"}]},
    "inventory": {"created": "2026-01-10T00:00:00.000Z"},
    "softwareListData": {
        "software": [
            {"id": 1, "fullName": "OpenSSL 3.0.2", "version": "3.0.2"},
            {"id": 2, "fullName": "nginx 1.18", "version": "1.18"},
        ]
    },
    "openPortListData": {
        "openPort": [{"port": 443, "protocol": "TCP", "detectedService": "https"}]
    },
}


def _page(assets: list[dict], *, has_more: int, last_seen=None) -> dict:
    return {
        "responseCode": "SUCCESS",
        "count": len(assets),
        "hasMore": has_more,
        "lastSeenAssetId": last_seen,
        "assetListData": {"asset": assets},
    }


def _query(call: responses.Call) -> dict:
    return {k: v[0] for k, v in parse_qs(urlparse(call.request.url).query).items()}


@responses.activate
def test_assets_paginate_and_explode_software_and_ports() -> None:
    responses.add(responses.POST, AUTH_URL, body="jwt-token", status=201)
    responses.add(
        responses.POST,
        SEARCH_URL,
        json=_page([ASSET], has_more=1, last_seen=2001),
        status=200,
    )
    responses.add(
        responses.POST,
        SEARCH_URL,
        json=_page([{"assetId": 2002, "assetName": "db-01"}], has_more=0),
        status=200,
    )

    ccm = CCM("qualys_gav", CONFIG)
    assets = ccm.collect("assets")
    software = ccm.collect("asset_software")
    ports = ccm.collect("asset_open_ports")

    assert list(assets["asset_id"]) == ["2001", "2002"]
    assert assets.loc[0, "host_id"] == "3077710"
    assert assets.loc[0, "os_full_name"] == "Ubuntu 22.04"
    assert assets.loc[0, "criticality_score"] == 3
    assert json.loads(assets.loc[0, "tags"]) == [{"tagId": 1, "tagName": "Prod"}]
    assert assets.loc[0, "created"].isoformat() == "2026-01-10T00:00:00+00:00"

    assert list(software["full_name"]) == ["OpenSSL 3.0.2", "nginx 1.18"]
    assert set(software["asset_id"]) == {"2001"}
    assert list(ports["port"]) == [443]
    assert ports.loc[0, "asset_name"] == "web-01"

    auth, first, second = responses.calls
    assert "token=true" in auth.request.body
    assert first.request.headers["Authorization"] == "Bearer jwt-token"
    assert _query(first) == {"pageSize": "300"}
    assert _query(second) == {"pageSize": "300", "lastSeenAssetId": "2001"}
    assert len(responses.calls) == 3  # derived resources replayed from cache


@responses.activate
def test_filters_and_asset_last_updated_kwargs() -> None:
    responses.add(responses.POST, AUTH_URL, body="jwt-token", status=201)
    responses.add(responses.POST, SEARCH_URL, json=_page([], has_more=0), status=200)
    criteria = [{"field": "asset.name", "operator": "EQUALS", "value": "web-01"}]

    df = CCM("qualys_gav", CONFIG).collect(
        "assets", filters=criteria, asset_last_updated="2026-10-01T00:00Z"
    )

    assert len(df) == 0
    search = responses.calls[1]
    assert json.loads(search.request.body) == {"filters": criteria}
    assert _query(search)["assetLastUpdated"] == "2026-10-01T00:00Z"


@responses.activate
def test_token_expiry_is_tracked_for_proactive_refresh() -> None:
    responses.add(responses.POST, AUTH_URL, body="jwt-token", status=201)
    responses.add(responses.POST, SEARCH_URL, json=_page([], has_more=0), status=200)

    ccm = CCM("qualys_gav", CONFIG)
    ccm.collect("assets")

    remaining = ccm._token_expires_at - datetime.now(timezone.utc)
    assert 3.9 * 3600 < remaining.total_seconds() <= 4 * 3600


@responses.activate
def test_bad_credentials_raise_authentication_error() -> None:
    responses.add(responses.POST, AUTH_URL, status=401)

    ccm = CCM("qualys_gav", CONFIG)
    with pytest.raises(AuthenticationError):
        ccm.collect("assets")


@responses.activate
def test_more_assets_without_cursor_raises() -> None:
    responses.add(responses.POST, AUTH_URL, body="jwt-token", status=201)
    responses.add(
        responses.POST, SEARCH_URL, json=_page([ASSET], has_more=1), status=200
    )

    ccm = CCM("qualys_gav", CONFIG)
    with pytest.raises(IncompleteCollection, match="lastSeenAssetId"):
        ccm.collect("assets")
