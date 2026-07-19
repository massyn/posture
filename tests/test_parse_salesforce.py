import json
from pathlib import Path

from posture.collectors.salesforce import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "salesforce"

DOMAIN_MANIFEST = MANIFEST["domain__c"]


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())["records"]


def test_domain_page() -> None:
    df = parse(_load("domain_page.json"), DOMAIN_MANIFEST, resource="domain__c")

    assert len(df) == 2
    assert df.loc[0, "id"] == "001"
    assert df.loc[0, "name"] == "example.com"
    assert bool(df.loc[0, "active__c"]) is True
    assert bool(df.loc[1, "active__c"]) is False


def test_manifest_query_matches_declared_columns() -> None:
    for table, definition in MANIFEST.items():
        fields = [source for source, _dtype in definition["columns"].values()]
        expected_query = f"select {','.join(fields)} from {table}"
        assert definition["query"] == expected_query
