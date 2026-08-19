import json
from pathlib import Path

import pandas as pd

from posture.collectors.whistic import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "whistic"

VENDORS_MANIFEST = MANIFEST["vendors"]
VENDOR_DETAILS_MANIFEST = MANIFEST["vendor_details"]


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_vendors_page() -> None:
    df = parse(_load("vendors_page.json"), VENDORS_MANIFEST, resource="vendors")

    assert len(df) == 2
    assert df.loc[0, "name"] == "Acme Corp"
    assert df.loc[0, "status"] == "ACTIVE"
    assert df.loc[0, "score"] == 82
    assert df.loc[0, "score_rating"] == "AVERAGE"
    assert df.loc[0, "inherent_risk"] == "High"
    assert df.loc[0, "criticality"] == "Mission Critical"
    assert df["created_date"].dtype == "datetime64[us, UTC]"
    assert pd.isna(df.loc[1, "score"])  # absent in fixture


def test_vendor_details_page() -> None:
    df = parse(
        _load("vendor_details_page.json"),
        VENDOR_DETAILS_MANIFEST,
        resource="vendor_details",
    )

    assert len(df) == 2
    assert df.loc[0, "description"] == "Provides cloud storage services."
    assert df.loc[0, "contract_value"] == "$50,000/year"
    assert df.loc[0, "billing_address_city"] == "Salt Lake City"
    assert df.loc[0, "business_unit"] == "Engineering"
    assert df.loc[0, "renewal_frequency"] == 1
    assert df.loc[0, "renewal_cadence"] == "YEARS"
    assert bool(df.loc[0, "enable_smart_search"]) is True
    assert json.loads(df.loc[0, "external_contacts"])[0]["email"] == (
        "jane@acme.example.com"
    )
    assert pd.isna(df.loc[1, "description"])  # absent in fixture
