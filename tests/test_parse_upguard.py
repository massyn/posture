import json
from pathlib import Path

import pandas as pd

from posture.collectors.upguard import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "upguard"

VENDORS_MANIFEST = MANIFEST["vendors"]
ORGANISATION_MANIFEST = MANIFEST["organisation"]
VENDOR_RISKS_MANIFEST = MANIFEST["vendor_risks"]


def _load(name: str) -> list[dict] | dict:
    return json.loads((FIXTURES / name).read_text())


def test_vendors_page() -> None:
    df = parse(_load("vendors_page.json"), VENDORS_MANIFEST, resource="vendors")

    assert len(df) == 2
    assert df.loc[0, "vendor_id"] == "vendor-1"
    assert df.loc[0, "score"] == 850
    assert df.loc[0, "website_security_score"] == 90
    assert bool(df.loc[0, "monitored"]) is True
    assert bool(df.loc[1, "monitored"]) is False
    assert df["last_assessed"].dtype == "datetime64[ns, UTC]"
    assert pd.isna(df.loc[1, "last_assessed"])  # absent in fixture


def test_organisation_single_object() -> None:
    df = parse(
        [_load("organisation.json")], ORGANISATION_MANIFEST, resource="organisation"
    )

    assert len(df) == 1
    assert df.loc[0, "organisation_id"] == "org-1"
    assert df.loc[0, "automated_score"] == 900
    assert df.loc[0, "email_security_score"] == 88


def test_vendor_risks_page_with_injected_hostname() -> None:
    df = parse(
        _load("vendor_risks_page.json"), VENDOR_RISKS_MANIFEST, resource="vendor_risks"
    )

    assert len(df) == 1
    assert df.loc[0, "risk_id"] == "risk-1"
    assert df.loc[0, "requested_primary_hostname"] == "acme.example.com"
    assert df.loc[0, "severity"] == "medium"
