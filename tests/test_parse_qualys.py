from pathlib import Path
from xml.etree import ElementTree

import pandas as pd

from posture.collectors.qualys import MANIFEST, _xml_to_dict
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "qualys"

HOSTS_MANIFEST = MANIFEST["hosts"]
VULNERABILITIES_MANIFEST = MANIFEST["vulnerabilities"]
VULNERABILITY_DETECTIONS_MANIFEST = MANIFEST["vulnerability_detections"]


def _load_records(name: str, list_path: str) -> list[dict]:
    root = ElementTree.fromstring((FIXTURES / name).read_bytes())
    return [_xml_to_dict(elem) for elem in root.findall(list_path)]


def test_hosts_page() -> None:
    records = _load_records("hosts_page.xml", "./RESPONSE/HOST_LIST/HOST")
    df = parse(records, HOSTS_MANIFEST, resource="hosts")

    assert len(df) == 2
    assert df.loc[0, "host_id"] == "12345"
    assert df.loc[0, "ip"] == "10.0.0.5"
    assert df.loc[0, "agent_version"] == "5.2.1"
    assert df.loc[0, "agent_status"] == "Activated"
    assert df.loc[0, "tags"] == (
        '[{"TAG_ID": "1", "NAME": "Production"}, {"TAG_ID": "2", "NAME": "Windows"}]'
    )
    assert df["last_boot"].dtype == "datetime64[ns, UTC]"

    # host2 has no AGENT_INFO element at all
    assert pd.isna(df.loc[1, "agent_version"])
    assert pd.isna(df.loc[1, "agent_status"])
    # host2's LAST_VULN_SCAN_DATETIME is garbage -> NaT, not a raised error
    assert pd.isna(df.loc[1, "last_vuln_scan_datetime"])


def test_vulnerabilities_page() -> None:
    records = _load_records("vulnerabilities_page.xml", "./RESPONSE/VULN_LIST/VULN")
    df = parse(records, VULNERABILITIES_MANIFEST, resource="vulnerabilities")

    assert len(df) == 2
    assert df.loc[0, "qid"] == "38170"
    assert df.loc[0, "severity_level"] == 5
    assert bool(df.loc[0, "patchable"]) is True
    assert df.loc[0, "cvss_base"] == 9.8
    assert df.loc[0, "cvss3_base"] == 9.8
    assert df.loc[0, "cve_list"] == (
        '[{"ID": "CVE-2026-1111", "URL": "https://cve.example.com/CVE-2026-1111"}, '
        '{"ID": "CVE-2026-1112", "URL": "https://cve.example.com/CVE-2026-1112"}]'
    )

    # second VULN has no CVSS/CVSS_V3/CVE_LIST elements at all
    assert pd.isna(df.loc[1, "cvss_base"])
    assert pd.isna(df.loc[1, "cvss3_base"])
    assert pd.isna(df.loc[1, "cve_list"])


def test_vulnerability_detections_explodes_per_host_and_preserves_grain() -> None:
    records = _load_records("host_detections_page.xml", "./RESPONSE/HOST_LIST/HOST")
    df = parse(
        records, VULNERABILITY_DETECTIONS_MANIFEST, resource="vulnerability_detections"
    )

    # host1 -> 2 detections, host2 -> 1 detection, host3 -> 0 detections (no
    # DETECTION_LIST element at all) -> zero rows for host3, never a
    # null-padded row.
    assert len(df) == 3
    assert set(df["host_id"]) == {"12345", "67890"}

    host1_rows = df[df["host_id"] == "12345"]
    assert len(host1_rows) == 2
    assert set(host1_rows["qid"]) == {"38170", "105432"}
    assert bool(host1_rows[host1_rows["qid"] == "105432"]["is_ignored"].iloc[0]) is True

    host2_row = df[df["host_id"] == "67890"].iloc[0]
    assert host2_row["host_dns"] == "host2.example.com"
    assert host2_row["status"] == "Fixed"
    assert host2_row["port"] == 22
