from pathlib import Path

import pandas as pd

from posture.collectors.cve_db import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "cve_db"

CVE_SUMMARY_MANIFEST = MANIFEST["cve_summary"]
CVE_CPE_MANIFEST = MANIFEST["cve_cpe"]


def _clean_records(path: Path) -> list[dict]:
    df = pd.read_parquet(path).astype(object)
    df = df.where(df != "N/A", None)
    df = df.where(df.notna(), None)
    return df.to_dict("records")


def test_cve_summary_page() -> None:
    records = _clean_records(FIXTURES / "cve_summary_2024.parquet")

    df = parse(records, CVE_SUMMARY_MANIFEST, resource="cve_summary")

    assert len(df) == 2
    assert df["published"].dtype == "datetime64[us, UTC]"
    assert df["kev_date_added"].dtype == "datetime64[us, UTC]"

    first = df.loc[0]
    assert first["cve_id"] == "CVE-2024-0001"
    assert first["is_kev"] == 1
    assert first["base_score"] == 7.5

    second = df.loc[1]
    assert pd.isna(second["base_score"])
    assert pd.isna(second["kev_date_added"])
    assert second["cwe"] is None


def test_cve_cpe_page() -> None:
    records = _clean_records(FIXTURES / "cve_cpe_2024.parquet")

    df = parse(records, CVE_CPE_MANIFEST, resource="cve_cpe")

    assert len(df) == 1
    row = df.loc[0]
    assert row["cve_id"] == "CVE-2024-0001"
    assert row["vendor"] == "acme"
    assert row["vulnerable"] == 1
    assert row["version_start_including"] is None
