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
            "general": {"device_id": "1", "device_name": "MAC-1"},
            "hardware_overview": {"serial_number": "SN-1"},
            "mdm": {"supervised": "True"},
            "filevault": {"filevault_enabled": True},
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
    assert bool(df.loc[0, "is_supervised"]) is True
    assert bool(df.loc[0, "filevault_enabled"]) is True


@responses.activate
def test_device_parameters_fans_out_and_explodes() -> None:
    responses.add(
        responses.GET,
        "https://example.api.kandji.io/api/v1/devices",
        json=[{"device_id": "1"}],
        status=200,
    )
    responses.add(
        responses.GET,
        "https://example.api.kandji.io/api/v1/devices/1/parameters",
        json={
            "device_id": "1",
            "parameters": [
                {"item_id": "p1", "name": "Enable Firewall", "status": "PASS"},
                {"item_id": "p2", "name": "Enable Gatekeeper", "status": "FAIL"},
            ],
        },
        status=200,
    )

    ccm = CCM(
        "kandji",
        {"api_url": "https://example.api.kandji.io", "api_token": "tok"},
    )
    df = ccm.collect("device_parameters")

    assert len(df) == 2
    assert set(df["device_id"]) == {"1"}
    assert set(df["name"]) == {"Enable Firewall", "Enable Gatekeeper"}


@responses.activate
def test_device_library_items_fans_out_and_explodes() -> None:
    responses.add(
        responses.GET,
        "https://example.api.kandji.io/api/v1/devices",
        json=[{"device_id": "1"}],
        status=200,
    )
    responses.add(
        responses.GET,
        "https://example.api.kandji.io/api/v1/devices/1/status",
        json={
            "device_id": "1",
            "library_items": [
                {"id": 42, "item_id": "li1", "name": "Falcon", "status": "PASS"},
            ],
        },
        status=200,
    )

    ccm = CCM(
        "kandji",
        {"api_url": "https://example.api.kandji.io", "api_token": "tok"},
    )
    df = ccm.collect("device_library_items")

    assert len(df) == 1
    assert df.loc[0, "device_id"] == "1"
    assert df.loc[0, "library_item_row_id"] == "42"
    assert df.loc[0, "name"] == "Falcon"


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
