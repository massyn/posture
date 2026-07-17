import json
from pathlib import Path

from posture.collectors.mde import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "mde"

MACHINES_MANIFEST = MANIFEST["machines"]
VULNERABILITIES_MANIFEST = MANIFEST["vulnerabilities"]
MACHINE_VULNERABILITIES_MANIFEST = MANIFEST["machine_vulnerabilities"]


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_machines_page() -> None:
    df = parse(_load("machines_page.json"), MACHINES_MANIFEST, resource="machines")

    assert len(df) == 2
    assert df.loc[0, "machine_id"] == "machine-1"
    assert bool(df.loc[0, "is_aad_joined"]) is True
    assert df["last_seen"].dtype == "datetime64[ns, UTC]"


def test_vulnerabilities_page() -> None:
    df = parse(
        _load("vulnerabilities_page.json"),
        VULNERABILITIES_MANIFEST,
        resource="vulnerabilities",
    )

    assert len(df) == 1
    assert df.loc[0, "cvss_score"] == 8.1
    assert df.loc[0, "exposed_machines"] == 42
    assert bool(df.loc[0, "public_exploit"]) is True


def test_machine_vulnerabilities_page_with_injected_machine_id() -> None:
    df = parse(
        _load("machine_vulnerabilities_page.json"),
        MACHINE_VULNERABILITIES_MANIFEST,
        resource="machine_vulnerabilities",
    )

    assert len(df) == 1
    assert df.loc[0, "machine_id"] == "machine-1"
    assert df.loc[0, "cve_id"] == "CVE-2026-1111"
