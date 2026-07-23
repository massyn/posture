import responses

from posture import CCM


@responses.activate
def test_policies_pagination_stops_on_partial_page() -> None:
    responses.add(
        responses.POST,
        "https://example.jamfcloud.com/api/oauth/token",
        json={"access_token": "tok"},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://example.jamfcloud.com/api/v1/policies",
        json={"totalCount": 1, "results": [{"id": "10", "name": "Install Chrome"}]},
        status=200,
    )

    ccm = CCM(
        "jamf",
        {
            "url": "https://example.jamfcloud.com",
            "client_id": "id",
            "client_secret": "secret",
        },
    )
    df = ccm.collect("policies")

    assert len(df) == 1
    assert ccm.report("policies")["pages"] == 1


@responses.activate
def test_computers_inventory_detail_batches_ids_from_inventory() -> None:
    responses.add(
        responses.POST,
        "https://example.jamfcloud.com/api/oauth/token",
        json={"access_token": "tok"},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://example.jamfcloud.com/api/v2/computers-inventory",
        json={"totalCount": 1, "results": [{"id": "1"}]},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://example.jamfcloud.com/api/v2/computers-inventory-detail/1",
        json={
            "id": "1",
            "serialNumber": "SN-1",
            "general": {
                "name": "MAC-1",
                "lastContactTime": "2026-07-20T00:00:00Z",
            },
            "userAndLocation": {"email": "user@example.com"},
            "operatingSystem": {"version": "14.5"},
            "security": {
                "bootPartitionEncryptionDetails": {
                    "partitionFileVault2State": "ALL_ENCRYPTED"
                },
                "sipStatus": "ENABLED",
                "firewallEnabled": True,
                "autoLoginDisabled": True,
                "gatekeeperStatus": "APP_STORE_AND_IDENTIFIED_DEVELOPERS",
                "secureBootLevel": "FULL_SECURITY",
            },
        },
        status=200,
    )

    ccm = CCM(
        "jamf",
        {
            "url": "https://example.jamfcloud.com",
            "client_id": "id",
            "client_secret": "secret",
        },
    )
    df = ccm.collect("computers_inventory_detail")

    assert len(df) == 1
    assert df.loc[0, "computer_inventory_detail_id"] == "1"
    assert df.loc[0, "serial_number"] == "SN-1"
    assert df.loc[0, "hostname"] == "MAC-1"
    assert df.loc[0, "user_email"] == "user@example.com"
    assert df.loc[0, "operating_system_version"] == "14.5"
    assert df.loc[0, "boot_partition_filevault2_state"] == "ALL_ENCRYPTED"
    assert df.loc[0, "sip_status"] == "ENABLED"
    assert bool(df.loc[0, "firewall_enabled"]) is True
    assert bool(df.loc[0, "auto_login_disabled"]) is True
    assert df.loc[0, "gatekeeper_status"] == "APP_STORE_AND_IDENTIFIED_DEVELOPERS"
    assert df.loc[0, "secure_boot_level"] == "FULL_SECURITY"

    detail_request = responses.calls[-1].request
    assert "section=SECURITY" in detail_request.url
    assert "section=GENERAL" in detail_request.url
    assert "section=USER_AND_LOCATION" in detail_request.url
    assert "section=OPERATING_SYSTEM" in detail_request.url
