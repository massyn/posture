import json
import time
from pathlib import Path
from urllib.parse import parse_qs

import pytest
import responses

from posture import CCM
from posture.exceptions import IncompleteCollection

FIXTURES = Path(__file__).parent / "fixtures" / "uptimerobot"
GET_MONITORS = "https://api.uptimerobot.com/v2/getMonitors"


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def _last_body() -> dict:
    return {k: v[0] for k, v in parse_qs(responses.calls[-1].request.body).items()}


@responses.activate
def test_monitors_collects_and_reshapes_ratios() -> None:
    responses.add(
        responses.POST, GET_MONITORS, json=_fixture("getmonitors_monitors.json")
    )

    df = CCM("uptimerobot", {"token": "ur-key"}).collect("monitors")

    assert list(df["friendly_name"]) == ["bouts.co.za", "budget.massyn.net"]
    assert df.loc[0, "uptime_ratio_7d"] == 99.696
    body = _last_body()
    assert body["api_key"] == "ur-key"
    assert body["custom_uptime_ratios"] == "1-7-30-90"
    assert "logs" not in body


@responses.activate
def test_monitor_logs_default_window_is_48h() -> None:
    responses.add(responses.POST, GET_MONITORS, json=_fixture("getmonitors_logs.json"))

    before = int(time.time())
    df = CCM("uptimerobot", {"token": "k"}).collect("monitor_logs")
    after = int(time.time())

    assert len(df) == 2
    assert list(df["reason_code"]) == ["200", "502"]
    body = _last_body()
    assert body["logs"] == "1"
    start, end = int(body["logs_start_date"]), int(body["logs_end_date"])
    assert before <= end <= after
    assert end - start == 48 * 3600
    assert "logs_window_hours" not in body


@responses.activate
def test_monitor_logs_window_hours_override() -> None:
    responses.add(responses.POST, GET_MONITORS, json=_fixture("getmonitors_logs.json"))

    CCM("uptimerobot", {"token": "k"}).collect("monitor_logs", logs_window_hours=6)

    body = _last_body()
    assert int(body["logs_end_date"]) - int(body["logs_start_date"]) == 6 * 3600
    assert "logs_window_hours" not in body


@responses.activate
def test_monitor_logs_since_datetime() -> None:
    responses.add(responses.POST, GET_MONITORS, json=_fixture("getmonitors_logs.json"))

    CCM("uptimerobot", {"token": "k"}).collect(
        "monitor_logs", logs_start_date="2026-01-01T00:00:00Z"
    )

    body = _last_body()
    assert body["logs_start_date"] == "1767225600"


@responses.activate
def test_monitor_logs_rejects_conflicting_window_kwargs() -> None:
    responses.add(responses.POST, GET_MONITORS, json=_fixture("getmonitors_logs.json"))

    with pytest.raises((ValueError, IncompleteCollection)):
        CCM("uptimerobot", {"token": "k"}).collect(
            "monitor_logs", logs_window_hours=6, logs_start_date=1767225600
        )


@responses.activate
def test_monitor_response_times_explode() -> None:
    responses.add(
        responses.POST, GET_MONITORS, json=_fixture("getmonitors_response_times.json")
    )

    df = CCM("uptimerobot", {"token": "k"}).collect("monitor_response_times")

    assert list(df["response_time_ms"]) == [1330, 1353, 210]


@responses.activate
def test_account_single_row() -> None:
    responses.add(
        responses.POST,
        "https://api.uptimerobot.com/v2/getAccountDetails",
        json=_fixture("getaccountdetails.json"),
    )

    df = CCM("uptimerobot", {"token": "k"}).collect("account")

    assert len(df) == 1
    assert df.loc[0, "down_monitors"] == 1


@responses.activate
def test_alert_contacts() -> None:
    responses.add(
        responses.POST,
        "https://api.uptimerobot.com/v2/getAlertContacts",
        json=_fixture("getalertcontacts.json"),
    )

    df = CCM("uptimerobot", {"token": "k"}).collect("alert_contacts")

    assert list(df["id"]) == ["6632892", "6632999"]


@responses.activate
def test_monitors_pagination_follows_total() -> None:
    page1 = _fixture("getmonitors_monitors.json")
    page1["pagination"] = {"offset": 0, "limit": 50, "total": 60}
    page2 = _fixture("getmonitors_monitors.json")
    page2["pagination"] = {"offset": 50, "limit": 50, "total": 60}
    responses.add(responses.POST, GET_MONITORS, json=page1)
    responses.add(responses.POST, GET_MONITORS, json=page2)

    df = CCM("uptimerobot", {"token": "k"}).collect("monitors")

    assert len(df) == 4
    assert len(responses.calls) == 2


@responses.activate
def test_invalid_api_key_raises_incomplete_collection() -> None:
    responses.add(
        responses.POST,
        GET_MONITORS,
        json={
            "stat": "fail",
            "error": {
                "type": "invalid_parameter",
                "parameter_name": "api_key",
                "message": "api_key is invalid.",
            },
        },
    )

    with pytest.raises(IncompleteCollection):
        CCM("uptimerobot", {"token": "bad"}).collect("monitors")
