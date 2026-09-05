from pathlib import Path

import pandas as pd
import responses

from posture import CCM

FIXTURES = Path(__file__).parent / "fixtures" / "cve_db"

_SUMMARY_URL = "https://cve-db.pages.dev/cve_summary_2024.parquet"
_CPE_URL = "https://cve-db.pages.dev/cve_cpe_2024.parquet"

_MANIFEST_JSON = {
    "_meta": {"tables": ["cve_summary", "cve_cpe"], "total_cves": 2},
    "cve_summary": {"files": {"parquet": [_SUMMARY_URL]}},
    "cve_cpe": {"files": {"parquet": [_CPE_URL]}},
}


def _register_manifest_and_files() -> None:
    responses.add(
        responses.GET,
        "https://cve-db.pages.dev/manifest.json",
        json=_MANIFEST_JSON,
        status=200,
    )
    responses.add(
        responses.GET,
        _SUMMARY_URL,
        body=(FIXTURES / "cve_summary_2024.parquet").read_bytes(),
        status=200,
        content_type="application/octet-stream",
    )
    responses.add(
        responses.GET,
        _CPE_URL,
        body=(FIXTURES / "cve_cpe_2024.parquet").read_bytes(),
        status=200,
        content_type="application/octet-stream",
    )


@responses.activate
def test_cve_summary_collects_and_normalises_na_sentinel() -> None:
    _register_manifest_and_files()

    ccm = CCM("cve_db")
    df = ccm.collect("cve_summary")

    assert len(df) == 2
    first, second = df.loc[0], df.loc[1]
    assert first["cve_id"] == "CVE-2024-0001"
    assert first["is_kev"] == 1
    assert first["base_score"] == 7.5
    assert pd.notna(first["kev_date_added"])

    # "N/A" sentinel values normalise to null, not the literal string.
    assert second["cve_id"] == "CVE-2024-0002"
    assert pd.isna(second["base_score"])
    assert pd.isna(second["epss"])
    assert pd.isna(second["kev_date_added"])
    assert second["cwe"] is None


@responses.activate
def test_empty_string_sentinel_on_cvss_flags_normalises_to_null() -> None:
    # Pre-CVSS-era CVEs (verified against the real cve_summary_1999.parquet
    # file) carry an empty string, not "N/A", on exactly the CVSS-derived
    # flag columns — the same "no CVSS vector to derive this from" null, just
    # a different sentinel literal.
    responses.add(
        responses.GET,
        "https://cve-db.pages.dev/manifest.json",
        json=_MANIFEST_JSON,
        status=200,
    )
    df = pd.DataFrame(
        [
            {
                "cve_id": "CVE-1999-0020",
                "is_remote": "",
                "is_adjacent": "",
                "cvss_version": "N/A",
            }
        ]
    )
    responses.add(
        responses.GET,
        _SUMMARY_URL,
        body=df.to_parquet(),
        status=200,
        content_type="application/octet-stream",
    )

    ccm = CCM("cve_db")
    out = ccm.collect("cve_summary")

    assert pd.isna(out.loc[0, "is_remote"])
    assert pd.isna(out.loc[0, "is_adjacent"])
    assert pd.isna(out.loc[0, "cvss_version"]) or out.loc[0, "cvss_version"] is None


@responses.activate
def test_cve_cpe_collects_from_its_own_files() -> None:
    _register_manifest_and_files()

    ccm = CCM("cve_db")
    df = ccm.collect("cve_cpe")

    assert len(df) == 1
    assert df.loc[0, "cve_id"] == "CVE-2024-0001"
    assert df.loc[0, "vendor"] == "acme"
    assert df.loc[0, "vulnerable"] == 1


@responses.activate
def test_manifest_json_fetched_once_across_resources() -> None:
    _register_manifest_and_files()

    ccm = CCM("cve_db")
    ccm.collect("cve_summary")
    ccm.collect("cve_cpe")

    manifest_calls = [
        c for c in responses.calls if c.request.url.endswith("manifest.json")
    ]
    assert len(manifest_calls) == 1
