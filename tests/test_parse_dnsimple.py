import json
from pathlib import Path

import pandas as pd

from posture.collectors.dnsimple import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "dnsimple"

DOMAINS_MANIFEST = MANIFEST["domains"]
ZONE_RECORDS_MANIFEST = MANIFEST["zone_records"]


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_domains_page() -> None:
    df = parse(_load("domains_page.json"), DOMAINS_MANIFEST, resource="domains")

    assert len(df) == 2
    assert df.loc[0, "name"] == "example.com"
    assert df.loc[0, "state"] == "registered"
    assert bool(df.loc[0, "auto_renew"]) is True
    assert df.loc[0, "registrant_id"] == "2715"
    assert df["expires_at"].dtype == "datetime64[us, UTC]"
    assert pd.isna(df.loc[1, "registrant_id"])  # hosted-only domain, no registrant
    assert pd.isna(df.loc[1, "expires_at"])  # not registered through DNSimple


def test_zone_records_page() -> None:
    records = _load("zone_records_page.json")
    for record in records:  # injected client-side by _fetch_records_for_zone
        record["_zone"] = "example.com"

    df = parse(records, ZONE_RECORDS_MANIFEST, resource="zone_records")

    assert len(df) == 3
    assert (df["zone"] == "example.com").all()
    assert df.loc[0, "type"] == "SOA"
    assert bool(df.loc[0, "system_record"]) is True
    assert df.loc[1, "name"] == "www"
    assert df.loc[2, "priority"] == 20
    assert df["created_at"].dtype == "datetime64[us, UTC]"
    assert pd.isna(df.loc[1, "priority"])  # CNAME has no priority
