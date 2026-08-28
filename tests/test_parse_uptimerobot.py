import json
from pathlib import Path

import pandas as pd

from posture.collectors.uptimerobot import MANIFEST, _reshape_monitor, _to_epoch
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "uptimerobot"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def test_monitors_reshapes_custom_ratio_strings_into_columns() -> None:
    monitors = [
        _reshape_monitor(m) for m in _load("getmonitors_monitors.json")["monitors"]
    ]
    df = parse(monitors, MANIFEST["monitors"], resource="monitors")

    assert list(df["friendly_name"]) == ["bouts.co.za", "budget.massyn.net"]
    assert df.loc[0, "uptime_ratio_1d"] == 97.874
    assert df.loc[0, "uptime_ratio_90d"] == 99.976
    assert df.loc[0, "down_duration_30d"] == 1837
    assert df.loc[1, "down_duration_1d"] == 0
    assert df.loc[0, "average_response_time"] == 1341.5
    assert df.loc[0, "all_time_uptime_ratio"] == 100.0
    assert df["create_datetime"].dtype == "datetime64[us, UTC]"
    # http credentials are never surfaced as columns
    assert "http_password" not in df.columns


def test_monitor_logs_explode_to_one_row_per_event() -> None:
    payload = _load("getmonitors_logs.json")
    records = [
        {"monitor_id": m["id"], "monitor_friendly_name": m["friendly_name"], **log}
        for m in payload["monitors"]
        for log in m.get("logs") or []
    ]
    df = parse(records, MANIFEST["monitor_logs"], resource="monitor_logs")

    assert len(df) == 2  # second monitor has no logs -> no rows
    assert list(df["monitor_id"]) == ["803132719", "803132719"]
    assert list(df["type"]) == [2, 1]
    assert df.loc[1, "reason_code"] == "502"
    assert df.loc[1, "reason_detail"] == "Bad Gateway"
    assert df.loc[1, "duration"] == 1837
    assert df["datetime"].dtype == "datetime64[us, UTC]"


def test_monitor_response_times_explode() -> None:
    payload = _load("getmonitors_response_times.json")
    records = [
        {
            "monitor_id": m["id"],
            "monitor_friendly_name": m["friendly_name"],
            "datetime": s["datetime"],
            "value": s["value"],
        }
        for m in payload["monitors"]
        for s in m.get("response_times") or []
    ]
    df = parse(
        records, MANIFEST["monitor_response_times"], resource="monitor_response_times"
    )

    assert len(df) == 3
    assert list(df["response_time_ms"]) == [1330, 1353, 210]


def test_account_single_row() -> None:
    df = parse(
        [_load("getaccountdetails.json")["account"]],
        MANIFEST["account"],
        resource="account",
    )

    assert len(df) == 1
    assert df.loc[0, "email"] == "ops@example.com"
    assert df.loc[0, "down_monitors"] == 1
    assert df["registered_at"].dtype == "datetime64[us, UTC]"
    assert df.loc[0, "registered_at"].year == 2024
    assert pd.isna(df.loc[0, "subscription_expiry_date"])


def test_alert_contacts_page() -> None:
    df = parse(
        _load("getalertcontacts.json")["alert_contacts"],
        MANIFEST["alert_contacts"],
        resource="alert_contacts",
    )

    assert list(df["id"]) == ["6632892", "6632999"]
    assert list(df["type"]) == [2, 5]
    assert df.loc[1, "friendly_name"] == "PagerDuty"


def test_to_epoch_accepts_int_and_iso() -> None:
    assert _to_epoch(1787909541) == 1787909541
    assert _to_epoch("1787909541") == 1787909541
    assert _to_epoch("2024-09-18T09:58:40Z") == 1726653520
