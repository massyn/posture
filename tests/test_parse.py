import json
from pathlib import Path

import pandas as pd

from posture.collectors.crowdstrike import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "crowdstrike"

HOSTS_MANIFEST = MANIFEST["hosts"]
HOSTS_COLUMNS = list(HOSTS_MANIFEST["columns"].keys())


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_hosts_page_normal() -> None:
    df = parse(_load("hosts_page.json"), HOSTS_MANIFEST, resource="hosts")

    assert list(df.columns) == HOSTS_COLUMNS
    assert len(df) == 2
    assert df.loc[0, "device_id"] == "aaa111"
    assert df.loc[0, "client_id"] == "cid-1"
    assert df.loc[0, "hostname"] == "host-a"
    assert bool(df.loc[0, "reduced_functionality_mode"]) is False
    assert bool(df.loc[1, "reduced_functionality_mode"]) is True
    assert df.loc[0, "host_status"] == "normal"
    assert df["last_seen"].dtype == "datetime64[ns, UTC]"
    assert df.loc[0, "last_seen"] == pd.Timestamp("2026-07-01T12:34:56Z")


def test_hosts_missing_optional_fields() -> None:
    df = parse(_load("hosts_missing_fields.json"), HOSTS_MANIFEST, resource="hosts")

    assert len(df) == 1
    assert df.loc[0, "device_id"] == "ccc333"
    assert df.loc[0, "client_id"] is None
    assert df.loc[0, "first_seen"] is pd.NaT


def test_hosts_bad_timestamps_become_nat() -> None:
    df = parse(_load("hosts_bad_timestamps.json"), HOSTS_MANIFEST, resource="hosts")

    assert len(df) == 2
    assert pd.isna(df.loc[0, "last_seen"])  # null value
    assert pd.isna(df.loc[1, "last_seen"])  # garbage string


def test_hosts_epoch_timestamps() -> None:
    df = parse(_load("hosts_epoch_timestamps.json"), HOSTS_MANIFEST, resource="hosts")

    assert df.loc[0, "last_seen"] == pd.Timestamp(1700000000, unit="s", tz="UTC")
    assert df.loc[1, "last_seen"] == pd.Timestamp(1700000000, unit="s", tz="UTC")


def test_empty_result_returns_declared_columns_zero_rows() -> None:
    df = parse([], HOSTS_MANIFEST, resource="hosts")

    assert list(df.columns) == HOSTS_COLUMNS
    assert len(df) == 0


DERIVED_MANIFEST = {
    "record_path": "children.items",
    "columns": {
        "parent_id": ("$parent.id", "str"),
        "child_id": ("id", "str"),
    },
}


def test_derived_resource_explosion_with_children() -> None:
    raw = [
        {
            "id": "parent-1",
            "children": {"items": [{"id": "child-1"}, {"id": "child-2"}]},
        }
    ]

    df = parse(raw, DERIVED_MANIFEST, resource="derived")

    assert len(df) == 2
    assert list(df["parent_id"]) == ["parent-1", "parent-1"]
    assert list(df["child_id"]) == ["child-1", "child-2"]


def test_derived_resource_zero_children_yields_zero_rows() -> None:
    raw = [{"id": "parent-1", "children": {"items": []}}]

    df = parse(raw, DERIVED_MANIFEST, resource="derived")

    assert len(df) == 0
    assert list(df.columns) == ["parent_id", "child_id"]


HOST_GROUPS_MANIFEST = MANIFEST["host_groups"]
HOST_GROUPS_COLUMNS = list(HOST_GROUPS_MANIFEST["columns"].keys())


def test_host_groups_page() -> None:
    df = parse(
        _load("host_groups_page.json"), HOST_GROUPS_MANIFEST, resource="host_groups"
    )

    assert list(df.columns) == HOST_GROUPS_COLUMNS
    assert len(df) == 2
    assert df.loc[0, "id"] == "hg-1"
    assert df.loc[0, "name"] == "Production servers"
    assert df.loc[0, "group_type"] == "dynamic"
    assert df["created_at"].dtype == "datetime64[ns, UTC]"
    assert df.loc[0, "created_at"] == pd.Timestamp("2026-01-01T00:00:00Z")
    assert pd.isna(df.loc[1, "description"])  # absent in fixture


VULNERABILITIES_MANIFEST = MANIFEST["vulnerabilities"]
REMEDIATIONS_MANIFEST = MANIFEST["vulnerability_remediations"]


def test_vulnerabilities_page() -> None:
    raw = _load("vulnerabilities_page.json")
    df = parse(raw, VULNERABILITIES_MANIFEST, resource="vulnerabilities")

    assert len(df) == 2
    assert "has_exploit" not in df.columns  # computed field, deliberately dropped
    assert "has_patch" not in df.columns
    assert df.loc[0, "cve_id"] == "CVE-2026-0001"
    assert bool(df.loc[0, "is_cisa_kev"]) is True
    assert df.loc[0, "exploit_status"] == 90
    assert pd.isna(df.loc[1, "description"])  # absent in fixture


def test_vulnerability_remediations_explosion() -> None:
    raw = _load("vulnerabilities_page.json")
    df = parse(raw, REMEDIATIONS_MANIFEST, resource="vulnerability_remediations")

    # vuln-1 has one remediation entity, vuln-2 has zero (grain is sacred).
    assert len(df) == 1
    assert df.loc[0, "id"] == "vuln-1"  # $parent.id, matches accelerator behaviour
    assert df.loc[0, "entity_id"] == "rem-1"
    assert df.loc[0, "action"] == "Update"


ZTA_MANIFEST = MANIFEST["zero_trust_assessment"]
ZTA_OS_SIGNALS_MANIFEST = MANIFEST["zero_trust_assessment_os_signals"]
ZTA_SENSOR_SIGNALS_MANIFEST = MANIFEST["zero_trust_assessment_sensor_signals"]


def test_zero_trust_assessment_page() -> None:
    df = parse(_load("zta_page.json"), ZTA_MANIFEST, resource="zero_trust_assessment")

    assert len(df) == 2
    assert df.loc[0, "assessment_overall"] == 85
    assert pd.isna(df.loc[1, "assessment_overall"])  # missing "assessment" dict


def test_zta_os_signals_are_tagged_with_literal_type() -> None:
    raw = _load("zta_page.json")
    df = parse(
        raw, ZTA_OS_SIGNALS_MANIFEST, resource="zero_trust_assessment_os_signals"
    )

    assert len(df) == 1
    assert df.loc[0, "type"] == "os_signals"
    assert df.loc[0, "aid"] == "agent-1"
    assert df.loc[0, "signal_id"] == "sig-1"


def test_zta_sensor_signals_are_tagged_and_independent_of_os_signals() -> None:
    raw = _load("zta_page.json")
    df = parse(
        raw,
        ZTA_SENSOR_SIGNALS_MANIFEST,
        resource="zero_trust_assessment_sensor_signals",
    )

    assert len(df) == 2
    assert list(df["type"]) == ["sensor_signals", "sensor_signals"]
    assert list(df["signal_id"]) == ["sig-2", "sig-3"]
