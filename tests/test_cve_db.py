import gzip
from pathlib import Path

import pandas as pd
import responses

from posture import CCM

FIXTURES = Path(__file__).parent / "fixtures" / "cve_db"

_SUMMARY_URL = "https://cve-db.pages.dev/cve_summary_2024.csv.gz"
_CPE_URL = "https://cve-db.pages.dev/cve_cpe_2024.csv.gz"

_MANIFEST_JSON = {
    "_meta": {"tables": {"cve_summary": 2, "cve_cpe": 2}},
    "cve_summary": {"files": {"csv": [_SUMMARY_URL]}},
    "cve_cpe": {"files": {"csv": [_CPE_URL]}},
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
        body=(FIXTURES / "cve_summary_2024.csv.gz").read_bytes(),
        status=200,
        content_type="application/octet-stream",
    )
    responses.add(
        responses.GET,
        _CPE_URL,
        body=(FIXTURES / "cve_cpe_2024.csv.gz").read_bytes(),
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
    # Pre-CVSS-era CVEs (verified against the real cve_summary_1999.csv.gz
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
        body=gzip.compress(df.to_csv(index=False).encode()),
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


def _register_year_files(rows_per_year: dict[int, int]) -> dict[int, str]:
    urls = {
        y: f"https://cve-db.pages.dev/cve_summary_{y}.csv.gz" for y in rows_per_year
    }
    responses.add(
        responses.GET,
        "https://cve-db.pages.dev/manifest.json",
        json={
            "_meta": {"tables": {"cve_summary": sum(rows_per_year.values())}},
            "cve_summary": {"files": {"csv": list(urls.values())}},
        },
        status=200,
    )
    for year, count in rows_per_year.items():
        df = pd.DataFrame({"cve_id": [f"CVE-{year}-{i:04d}" for i in range(count)]})
        responses.add(
            responses.GET,
            urls[year],
            body=gzip.compress(df.to_csv(index=False).encode()),
            status=200,
            content_type="application/octet-stream",
        )
    return urls


@responses.activate
def test_pages_are_row_count_bounded_and_span_years() -> None:
    _register_year_files({2022: 3, 2023: 4, 2024: 2})

    ccm = CCM("cve_db", {"page_size": 4})
    pages = list(ccm.collect_page("cve_summary"))

    # 9 rows in 4-row pages: the second page straddles 2022/2023 and 2023/2024
    # boundaries, only the last page is short.
    assert [len(p) for p in pages] == [4, 4, 1]
    assert list(pages[0]["cve_id"]) == [
        "CVE-2022-0000",
        "CVE-2022-0001",
        "CVE-2022-0002",
        "CVE-2023-0000",
    ]
    ids = [i for p in pages for i in p["cve_id"]]
    assert len(ids) == len(set(ids)) == 9
    assert ids[-1] == "CVE-2024-0001"


@responses.activate
def test_year_file_downloaded_once_across_its_pages() -> None:
    urls = _register_year_files({2022: 5, 2023: 5})

    ccm = CCM("cve_db", {"page_size": 2})
    ccm.collect("cve_summary")

    for url in urls.values():
        assert sum(1 for c in responses.calls if c.request.url == url) == 1


@responses.activate
def test_page_ending_exactly_on_year_boundary_loses_no_rows() -> None:
    _register_year_files({2022: 4, 2023: 4})

    ccm = CCM("cve_db", {"page_size": 4})
    pages = list(ccm.collect_page("cve_summary"))

    assert [len(p) for p in pages] == [4, 4]
    assert pages[1].loc[0, "cve_id"] == "CVE-2023-0000"


@responses.activate
def test_record_limit_applies_across_page_boundary() -> None:
    _register_year_files({2022: 3, 2023: 4})

    ccm = CCM("cve_db", {"page_size": 2}, record_limit=5)
    df = ccm.collect("cve_summary")

    assert len(df) == 5


def test_page_size_read_from_env_and_validated(monkeypatch) -> None:
    import pytest

    monkeypatch.setenv("CVE_DB_PAGE_SIZE", "1000")
    assert CCM("cve_db")._page_size == 1000

    with pytest.raises(ValueError):
        CCM("cve_db", {"page_size": 0})
