import json
from pathlib import Path

import pandas as pd

from posture.collectors.macadmins import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "macadmins"

RELEASES_MANIFEST = MANIFEST["macos_releases"]
CVES_MANIFEST = MANIFEST["macos_cves"]


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_macos_releases_page() -> None:
    df = parse(
        _load("macos_releases_page.json"), RELEASES_MANIFEST, resource="macos_releases"
    )

    assert len(df) == 2
    latest_row = df.loc[0]
    assert latest_row["os_version_name"] == "Sequoia 15"
    assert latest_row["product_version"] == "15.6"
    assert latest_row["build"] == "24G84"
    assert latest_row["unique_cves_count"] == 3
    assert latest_row["exploited_cve_count"] == 1
    assert df["release_date"].dtype == "datetime64[us, UTC]"

    # An older release of the same major version has no Build in the feed —
    # cross-referencing only populates it for the release matching Latest.
    older_row = df.loc[1]
    assert older_row["product_version"] == "15.5"
    assert pd.isna(older_row["build"])
    assert older_row["exploited_cve_count"] == 0


def test_macos_cves_derived_from_releases() -> None:
    df = parse(_load("macos_releases_page.json"), CVES_MANIFEST, resource="macos_cves")

    # 3 CVEs on 15.6, zero on 15.5 (empty _cves list yields zero rows for
    # that parent — grain is sacred, no null-padded row).
    assert len(df) == 3
    assert set(df["product_version"]) == {"15.6"}

    exploited = df[df["cve_id"] == "CVE-2026-11111"].iloc[0]
    assert bool(exploited["exploited"]) is True

    not_exploited = df[df["cve_id"] == "CVE-2026-22222"].iloc[0]
    assert bool(not_exploited["exploited"]) is False
