import json
from pathlib import Path

import pandas as pd

from posture.collectors.dnsimple import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "dnsimple"

DOMAINS_MANIFEST = MANIFEST["domains"]


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_domains_page() -> None:
    df = parse(_load("domains_page.json"), DOMAINS_MANIFEST, resource="domains")

    assert len(df) == 2
    assert df.loc[0, "name"] == "example.com"
    assert df.loc[0, "state"] == "registered"
    assert bool(df.loc[0, "auto_renew"]) is True
    assert df.loc[0, "registrant_id"] == "2715"
    assert df["expires_at"].dtype == "datetime64[ns, UTC]"
    assert pd.isna(df.loc[1, "registrant_id"])  # hosted-only domain, no registrant
    assert pd.isna(df.loc[1, "expires_at"])  # not registered through DNSimple
