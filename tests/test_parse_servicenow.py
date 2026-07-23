import json
from pathlib import Path

from posture.collectors.servicenow import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "servicenow"

CMDB_CI_MANIFEST = MANIFEST["cmdb_ci"]


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())["result"]


def test_cmdb_ci_page() -> None:
    df = parse(_load("cmdb_ci_page.json"), CMDB_CI_MANIFEST, resource="cmdb_ci")

    assert len(df) == 2
    assert df.loc[0, "sys_id"] == "001"
    assert df.loc[0, "name"] == "srv01"
    assert df.loc[1, "sys_class_name"] == "cmdb_ci_win_server"


def test_manifest_sysparm_fields_matches_declared_columns() -> None:
    for _table, definition in MANIFEST.items():
        fields = [source for source, _dtype in definition["columns"].values()]
        assert definition["sysparm_fields"] == ",".join(fields)
