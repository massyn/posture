import json
from pathlib import Path

import pandas as pd

from posture.collectors.healthchecks import MANIFEST, _to_epoch
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "healthchecks"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def test_checks_page() -> None:
    df = parse(_load("checks.json")["checks"], MANIFEST["checks"], resource="checks")

    assert list(df["name"]) == ["do3-heartbeat", "nightly-backup"]
    assert df.loc[0, "status"] == "up"
    assert df.loc[0, "grace"] == 60
    assert df.loc[0, "timeout"] == 120
    assert df.loc[0, "tags"] == "prod db"
    assert bool(df.loc[0, "started"]) is False
    assert df["last_ping"].dtype == "datetime64[us, UTC]"
    assert df.loc[0, "unique_key"] == "ea3b76a8041eee6ae48b08e567664a62fcef7768"
    # cron check: schedule/tz populated, timeout absent
    assert df.loc[1, "schedule"] == "0 2 * * *"
    assert df.loc[1, "tz"] == "Australia/Sydney"
    assert pd.isna(df.loc[1, "timeout"])
    assert df.loc[1, "uuid"] is None  # read-only key omits uuid


def test_flips_explode_with_injected_check_context() -> None:
    raw = _load("flips_heartbeat.json")["flips"]
    for record in raw:
        record["_check_key"] = "ea3b76a8"
        record["_check_name"] = "do3-heartbeat"
    df = parse(raw, MANIFEST["flips"], resource="flips")

    assert len(df) == 2
    assert list(df["up"]) == [1, 0]
    assert list(df["check_name"]) == ["do3-heartbeat", "do3-heartbeat"]
    assert df["timestamp"].dtype == "datetime64[us, UTC]"


def test_to_epoch_accepts_int_and_iso() -> None:
    assert _to_epoch(1740000000) == 1740000000
    assert _to_epoch("1740000000") == 1740000000
    assert _to_epoch("2026-01-01T00:00:00Z") == 1767225600
