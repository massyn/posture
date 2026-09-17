import responses

from posture import CCM

_FEED_URL = "https://sofafeed.macadmins.io/v1/macos_data_feed.json"

_FEED = {
    "UpdateHash": "abc123",
    "OSVersions": [
        {
            "OSVersion": "Sequoia 15",
            "Latest": {
                "ProductVersion": "15.6",
                "Build": "24G84",
            },
            "SecurityReleases": [
                {
                    "UpdateName": "macOS Sequoia 15.6",
                    "ProductName": "macOS",
                    "ProductVersion": "15.6",
                    "ReleaseDate": "2026-07-14T00:00:00Z",
                    "ReleaseType": "OS",
                    "SecurityInfo": "https://support.apple.com/en-us/121101",
                    "UniqueCVEsCount": 2,
                    "DaysSincePreviousRelease": 28,
                    "CVEs": {
                        "CVE-2026-11111": True,
                        "CVE-2026-22222": False,
                    },
                },
                {
                    "UpdateName": "macOS Sequoia 15.5",
                    "ProductName": "macOS",
                    "ProductVersion": "15.5",
                    "ReleaseDate": "2026-06-16T00:00:00Z",
                    "ReleaseType": "OS",
                    "SecurityInfo": "https://support.apple.com/en-us/121012",
                    "UniqueCVEsCount": 0,
                    "DaysSincePreviousRelease": 35,
                    "CVEs": {},
                },
            ],
        }
    ],
}


@responses.activate
def test_collect_macos_releases_no_credentials_needed() -> None:
    responses.add(responses.GET, _FEED_URL, json=_FEED, status=200)

    ccm = CCM("macadmins")
    df = ccm.collect("macos_releases")

    assert len(df) == 2
    latest = df[df["product_version"] == "15.6"].iloc[0]
    assert latest["build"] == "24G84"
    assert latest["exploited_cve_count"] == 1
    assert latest["unique_cves_count"] == 2

    older = df[df["product_version"] == "15.5"].iloc[0]
    assert older["build"] is None
    assert older["exploited_cve_count"] == 0


@responses.activate
def test_collect_macos_cves_derived() -> None:
    responses.add(responses.GET, _FEED_URL, json=_FEED, status=200)

    ccm = CCM("macadmins")
    df = ccm.collect("macos_cves")

    assert len(df) == 2
    assert set(df["product_version"]) == {"15.6"}
    exploited_row = df[df["cve_id"] == "CVE-2026-11111"].iloc[0]
    assert bool(exploited_row["exploited"]) is True
