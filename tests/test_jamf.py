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
        json={"id": "1", "serialNumber": "SN-1"},
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
