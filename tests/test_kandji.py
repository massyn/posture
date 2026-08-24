import responses

from posture import CCM


@responses.activate
def test_devices_pagination_stops_on_partial_page() -> None:
    responses.add(
        responses.GET,
        "https://example.api.kandji.io/api/v1/devices",
        json=[{"device_id": "1", "device_name": "MAC-1"}],
        status=200,
    )

    ccm = CCM(
        "kandji",
        {"api_url": "https://example.api.kandji.io", "api_token": "tok"},
    )
    df = ccm.collect("devices")

    assert len(df) == 1
    assert ccm.report("devices")["pages"] == 1


@responses.activate
def test_device_details_batches_ids_from_devices() -> None:
    responses.add(
        responses.GET,
        "https://example.api.kandji.io/api/v1/devices",
        json=[{"device_id": "1"}],
        status=200,
    )
    responses.add(
        responses.GET,
        "https://example.api.kandji.io/api/v1/devices/1/details",
        json={
            "device_id": "1",
            "serial_number": "SN-1",
            "security": {"filevault": {"enabled": True}},
        },
        status=200,
    )

    ccm = CCM(
        "kandji",
        {"api_url": "https://example.api.kandji.io", "api_token": "tok"},
    )
    df = ccm.collect("device_details")

    assert len(df) == 1
    assert df.loc[0, "device_id"] == "1"
    assert df.loc[0, "serial_number"] == "SN-1"
    assert bool(df.loc[0, "filevault_enabled"]) is True


@responses.activate
def test_blueprints_follows_next_url() -> None:
    responses.add(
        responses.GET,
        "https://example.api.kandji.io/api/v1/blueprints",
        json={
            "count": 2,
            "next": "https://example.api.kandji.io/api/v1/blueprints?page=2",
            "previous": None,
            "results": [{"id": "bp-1", "name": "Standard macOS"}],
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "https://example.api.kandji.io/api/v1/blueprints?page=2",
        json={
            "count": 2,
            "next": None,
            "previous": None,
            "results": [{"id": "bp-2", "name": "Kiosk iPad"}],
        },
        status=200,
    )

    ccm = CCM(
        "kandji",
        {"api_url": "https://example.api.kandji.io", "api_token": "tok"},
    )
    df = ccm.collect("blueprints")

    assert len(df) == 2
    assert ccm.report("blueprints")["pages"] == 2


@responses.activate
def test_vulnerabilities_page() -> None:
    responses.add(
        responses.GET,
        "https://example.api.kandji.io/api/v1/vulnerability-management/vulnerabilities",
        json={
            "count": 1,
            "next": None,
            "previous": None,
            "results": [{"id": "vuln-1", "cve_id": "CVE-2026-12345", "device_id": "1"}],
        },
        status=200,
    )

    ccm = CCM(
        "kandji",
        {"api_url": "https://example.api.kandji.io", "api_token": "tok"},
    )
    df = ccm.collect("vulnerabilities")

    assert len(df) == 1
    assert df.loc[0, "cve_id"] == "CVE-2026-12345"


@responses.activate
def test_api_url_normalizes_bare_host() -> None:
    responses.add(
        responses.GET,
        "https://example.api.kandji.io/api/v1/devices",
        json=[],
        status=200,
    )

    ccm = CCM("kandji", {"api_url": "example.api.kandji.io", "api_token": "tok"})
    df = ccm.collect("devices")

    assert len(df) == 0
