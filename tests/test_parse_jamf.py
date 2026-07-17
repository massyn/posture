import json
from pathlib import Path

import pandas as pd

from posture.collectors.jamf import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "jamf"

COMPUTERS_INVENTORY_MANIFEST = MANIFEST["computers_inventory"]
COMPUTERS_DETAIL_MANIFEST = MANIFEST["computers_inventory_detail"]
POLICIES_MANIFEST = MANIFEST["policies"]


def _load(name: str) -> list[dict] | dict:
    return json.loads((FIXTURES / name).read_text())


def test_computers_inventory_page() -> None:
    df = parse(
        _load("computers_inventory_page.json"),
        COMPUTERS_INVENTORY_MANIFEST,
        resource="computers_inventory",
    )

    assert len(df) == 2
    assert df.loc[0, "computer_id"] == "1"
    assert df.loc[0, "os_version"] == "14.5"
    assert df["last_inventory_update_timestamp"].dtype == "datetime64[ns, UTC]"
    assert pd.isna(df.loc[1, "last_inventory_update_timestamp"])  # absent in fixture
    assert pd.isna(df.loc[1, "os_version"])  # absent nested operatingSystem


def test_computers_inventory_detail() -> None:
    df = parse(
        [_load("computers_inventory_detail.json")],
        COMPUTERS_DETAIL_MANIFEST,
        resource="computers_inventory_detail",
    )

    assert len(df) == 1
    assert df.loc[0, "computer_inventory_detail_id"] == "1"
    assert df.loc[0, "serial_number"] == "SN-1"


def test_policies_page() -> None:
    df = parse(_load("policies_page.json"), POLICIES_MANIFEST, resource="policies")

    assert len(df) == 2
    assert bool(df.loc[0, "is_enabled"]) is True
    assert bool(df.loc[1, "is_enabled"]) is False
