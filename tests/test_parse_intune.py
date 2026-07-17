import json
from pathlib import Path

import pandas as pd

from posture.collectors.intune import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "intune"

MANAGED_DEVICES_MANIFEST = MANIFEST["managed_devices"]
DEVICE_CONFIGURATIONS_MANIFEST = MANIFEST["device_configurations"]
ATTACK_SIMULATIONS_MANIFEST = MANIFEST["attack_simulations"]
ATTACK_SIMULATION_USERS_MANIFEST = MANIFEST["attack_simulation_users"]


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_managed_devices_page() -> None:
    df = parse(
        _load("managed_devices_page.json"),
        MANAGED_DEVICES_MANIFEST,
        resource="managed_devices",
    )

    assert len(df) == 2
    assert df.loc[0, "device_id"] == "dev-1"
    assert df.loc[0, "os_version"] == "10.0.22631"
    assert pd.isna(df.loc[1, "os_version"])  # absent in fixture


def test_device_configurations_page() -> None:
    df = parse(
        _load("device_configurations_page.json"),
        DEVICE_CONFIGURATIONS_MANIFEST,
        resource="device_configurations",
    )

    assert len(df) == 1
    assert df.loc[0, "configuration_id"] == "cfg-1"
    assert json.loads(df.loc[0, "role_scope_tag_ids"]) == ["0"]
    assert json.loads(df.loc[0, "settings_json"]) == [{"key": "value"}]
    assert df["created_date_time"].dtype == "datetime64[ns, UTC]"


def test_attack_simulations_page_drops_odata_etag() -> None:
    df = parse(
        _load("attack_simulations_page.json"),
        ATTACK_SIMULATIONS_MANIFEST,
        resource="attack_simulations",
    )

    assert len(df) == 1
    assert "etag" not in df.columns
    assert df.loc[0, "created_by_email"] == "admin@example.com"
    assert bool(df.loc[0, "is_automated"]) is True
    assert json.loads(df.loc[0, "training_setting_json"]) == {"type": "assign"}


def test_attack_simulation_users_page() -> None:
    df = parse(
        _load("attack_simulation_users_page.json"),
        ATTACK_SIMULATION_USERS_MANIFEST,
        resource="attack_simulation_users",
    )

    assert len(df) == 2
    assert df.loc[0, "simulation_id"] == "sim-1"  # injected _simulation_id
    assert df.loc[0, "user_id"] == "99af58b9-ef1a-412b-a581-cb42fe8c8e21"
    assert bool(df.loc[0, "is_compromised"]) is True
    assert bool(df.loc[1, "is_compromised"]) is False
    assert json.loads(df.loc[0, "simulation_events_json"]) == [
        {
            "eventName": "SuccessfullyDeliveredEmail",
            "eventDateTime": "2026-01-01T01:01:01.01Z",
        }
    ]
    assert df["compromised_date_time"].dtype == "datetime64[ns, UTC]"
    assert pd.isna(df.loc[1, "compromised_date_time"])  # absent in fixture
