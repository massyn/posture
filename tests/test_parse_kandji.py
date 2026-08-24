import json
from pathlib import Path

import pandas as pd

from posture.collectors.kandji import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "kandji"

DEVICES_MANIFEST = MANIFEST["devices"]
DEVICE_DETAILS_MANIFEST = MANIFEST["device_details"]
BLUEPRINTS_MANIFEST = MANIFEST["blueprints"]
VULNERABILITIES_MANIFEST = MANIFEST["vulnerabilities"]


def _load(name: str) -> list[dict] | dict:
    return json.loads((FIXTURES / name).read_text())


def test_devices_page() -> None:
    df = parse(_load("devices_page.json"), DEVICES_MANIFEST, resource="devices")

    assert len(df) == 2
    assert df.loc[0, "device_id"] == "1"
    assert df.loc[0, "os_version"] == "14.5"
    assert df.loc[0, "user_email"] == "user@example.com"
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
    assert bool(df.loc[0, "filevault_enabled"]) is True
    assert bool(df.loc[0, "filevault_recovery_key_escrowed"]) is True
    assert bool(df.loc[0, "firewall_enabled"]) is True
    assert bool(df.loc[0, "gatekeeper_enabled"]) is True
    assert bool(df.loc[0, "sip_enabled"]) is True


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
