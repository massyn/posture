import json
from pathlib import Path

import pandas as pd

from posture.collectors.kandji import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "kandji"

DEVICES_MANIFEST = MANIFEST["devices"]
DEVICE_DETAILS_MANIFEST = MANIFEST["device_details"]
DEVICE_PARAMETERS_MANIFEST = MANIFEST["device_parameters"]
DEVICE_LIBRARY_ITEMS_MANIFEST = MANIFEST["device_library_items"]
BLUEPRINTS_MANIFEST = MANIFEST["blueprints"]
VULNERABILITIES_MANIFEST = MANIFEST["vulnerabilities"]


def _load(name: str) -> list[dict] | dict:
    return json.loads((FIXTURES / name).read_text())


def test_devices_page() -> None:
    df = parse(_load("devices_page.json"), DEVICES_MANIFEST, resource="devices")

    assert len(df) == 2
    assert df.loc[0, "device_id"] == "1"
    assert df.loc[0, "os_version"] == "14.5"
    assert df.loc[0, "udid"] == "UDID-1"
    assert df.loc[0, "blueprint_name"] == "Standard macOS"
    assert df.loc[0, "user_email"] == "user@example.com"
    assert df.loc[0, "user_name"] == "Test User"
    assert df.loc[0, "user_id"] == "u-1"
    assert df.loc[0, "tags"] == '["engineering", "laptop"]'
    assert df["last_check_in"].dtype == "datetime64[us, UTC]"
    assert pd.isna(df.loc[1, "last_check_in"])  # absent in fixture
    assert pd.isna(df.loc[1, "user_email"])  # absent nested user


def test_device_details() -> None:
    df = parse(
        [_load("device_details.json")],
        DEVICE_DETAILS_MANIFEST,
        resource="device_details",
    )

    assert len(df) == 1
    assert df.loc[0, "device_id"] == "1"
    assert df.loc[0, "serial_number"] == "SN-1"
    assert df.loc[0, "assigned_user_email"] == "user@example.com"
    assert df.loc[0, "blueprint_name"] == "Standard macOS"
    assert bool(df.loc[0, "mdm_enabled"]) is True
    assert bool(df.loc[0, "is_supervised"]) is True
    assert bool(df.loc[0, "filevault_enabled"]) is True
    assert bool(df.loc[0, "filevault_recovery_key_escrowed"]) is True
    assert bool(df.loc[0, "activation_lock_enabled"]) is False
    assert bool(df.loc[0, "remote_desktop_enabled"]) is False
    assert df["last_check_in"].dtype == "datetime64[us, UTC]"
    assert not pd.isna(df.loc[0, "filevault_next_rotation"])


def test_device_parameters_explodes_per_parameter() -> None:
    payload = _load("device_parameters.json")
    rows = [{**p, "device_id": payload["device_id"]} for p in payload["parameters"]]
    df = parse(rows, DEVICE_PARAMETERS_MANIFEST, resource="device_parameters")

    assert len(df) == 2
    assert set(df["device_id"]) == {"1"}
    assert df.loc[0, "name"] == "Enable System Integrity Protection"
    assert df.loc[0, "status"] == "PASS"
    assert df.loc[1, "status"] == "FAIL"


def test_device_library_items_explodes_per_item() -> None:
    payload = _load("device_library_items.json")
    rows = [{**i, "device_id": payload["device_id"]} for i in payload["library_items"]]
    df = parse(rows, DEVICE_LIBRARY_ITEMS_MANIFEST, resource="device_library_items")

    assert len(df) == 2
    assert df.loc[0, "library_item_row_id"] == "5031"
    assert df.loc[0, "type"] == "custom-app"
    assert bool(df.loc[0, "rules_present"]) is False
    assert pd.isna(df.loc[0, "reported_at"])
    assert not pd.isna(df.loc[1, "reported_at"])


def test_blueprints_page() -> None:
    payload = _load("blueprints_page.json")
    df = parse(payload["results"], BLUEPRINTS_MANIFEST, resource="blueprints")

    assert len(df) == 2
    assert df.loc[0, "blueprint_id"] == "bp-1"
    assert df.loc[1, "name"] == "Kiosk iPad"


def test_vulnerabilities_page() -> None:
    payload = _load("vulnerabilities_page.json")
    df = parse(payload["results"], VULNERABILITIES_MANIFEST, resource="vulnerabilities")

    assert len(df) == 1
    assert df.loc[0, "cve_id"] == "CVE-2026-12345"
    assert df.loc[0, "severity"] == "high"
    assert df.loc[0, "cvss_score"] == 8.1
