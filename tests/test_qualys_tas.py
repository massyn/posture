import json

import pytest
import responses

from posture import CCM
from posture.exceptions import IncompleteCollection

_BASE = "https://qualysapi.qualys.com"
_FINDING_URL = f"{_BASE}/qps/rest/3.0/search/was/finding"
_WEBAPP_URL = f"{_BASE}/qps/rest/3.0/search/was/webapp"
_CONFIG = {"username": "ccm", "password": "secret", "base_url": "qualysapi.qualys.com"}


def _service_response(
    entity: str, records: list[dict], *, has_more: bool = False, last_id=None
) -> dict:
    body = {
        "responseCode": "SUCCESS",
        "count": len(records),
        "hasMoreRecords": "true" if has_more else "false",
        "data": [{entity: record} for record in records],
    }
    if last_id is not None:
        body["lastId"] = last_id
    return {"ServiceResponse": body}


def _request(call: responses.Call) -> dict:
    return json.loads(call.request.body)["ServiceRequest"]


@responses.activate
def test_findings_paginate_on_last_id() -> None:
    responses.add(
        responses.POST,
        _FINDING_URL,
        json=_service_response(
            "Finding",
            [
                {
                    "id": 11,
                    "uniqueId": "u-11",
                    "qid": 150001,
                    "name": "Reflected XSS",
                    "type": "VULNERABILITY",
                    "severity": 4,
                    "status": "ACTIVE",
                    "potential": "false",
                    "cvssV3": {"base": 6.1, "attackVector": "Network"},
                    "cwe": {"count": 1, "list": [79]},
                    "webApp": {"id": 7, "name": "Shop", "url": "https://shop"},
                    "firstDetectedDate": "2026-09-01T10:00:00Z",
                    "isIgnored": "false",
                }
            ],
            has_more=True,
            last_id=11,
        ),
        status=200,
    )
    responses.add(
        responses.POST,
        _FINDING_URL,
        json=_service_response("Finding", [{"id": 12, "severity": 2}]),
        status=200,
    )

    ccm = CCM("qualys_tas", _CONFIG)
    df = ccm.collect("findings")

    assert list(df["id"]) == [11, 12]
    assert df.loc[0, "cvss_v3_base"] == 6.1
    assert df.loc[0, "cwe"] == "[79]"
    assert df.loc[0, "webapp_name"] == "Shop"
    assert bool(df.loc[0, "potential"]) is False
    assert df.loc[0, "first_detected_date"].isoformat() == "2026-09-01T10:00:00+00:00"
    assert ccm.report("findings")["pages"] == 2

    first, second = (_request(call) for call in responses.calls)
    assert first["preferences"] == {"limitResults": 1000, "verbose": False}
    assert "filters" not in first
    assert second["filters"]["Criteria"] == [
        {"field": "id", "operator": "GREATER", "value": 11}
    ]


@responses.activate
def test_filters_kwarg_is_sent_with_the_cursor() -> None:
    criteria = {"field": "severity", "operator": "GREATER", "value": 3}
    responses.add(
        responses.POST,
        _WEBAPP_URL,
        json=_service_response(
            "WebApp",
            [{"id": 7, "name": "Shop", "tags": {"count": 0, "list": []}}],
            has_more=True,
            last_id=7,
        ),
        status=200,
    )
    responses.add(
        responses.POST, _WEBAPP_URL, json=_service_response("WebApp", []), status=200
    )

    df = CCM("qualys_tas", _CONFIG).collect("webapps", filters=[criteria])

    assert list(df["id"]) == [7]
    first, second = (_request(call) for call in responses.calls)
    assert first["preferences"]["verbose"] is True
    assert first["filters"]["Criteria"] == [criteria]
    assert second["filters"]["Criteria"] == [
        criteria,
        {"field": "id", "operator": "GREATER", "value": 7},
    ]


@responses.activate
def test_non_success_response_code_raises() -> None:
    responses.add(
        responses.POST,
        _FINDING_URL,
        json={
            "ServiceResponse": {
                "responseCode": "INVALID_REQUEST",
                "responseErrorDetails": {"errorMessage": "bad criteria"},
            }
        },
        status=200,
    )

    ccm = CCM("qualys_tas", _CONFIG)
    with pytest.raises(IncompleteCollection, match="bad criteria"):
        ccm.collect("findings")


@responses.activate
def test_more_records_without_last_id_raises() -> None:
    responses.add(
        responses.POST,
        _FINDING_URL,
        json=_service_response("Finding", [{"id": 1}], has_more=True),
        status=200,
    )

    ccm = CCM("qualys_tas", _CONFIG)
    with pytest.raises(IncompleteCollection, match="no lastId"):
        ccm.collect("findings")


def test_unknown_kwarg_raises() -> None:
    ccm = CCM("qualys_tas", _CONFIG)
    with pytest.raises(IncompleteCollection, match="Unsupported kwargs"):
        ccm.collect("findings", qql="severity:5")
