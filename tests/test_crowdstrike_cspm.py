import requests
import responses

from posture import CCM


@responses.activate
def test_collector_follows_x_cs_region_to_correct_base_url() -> None:
    responses.add(
        responses.POST,
        "https://api.crowdstrike.com/oauth2/token",
        json={"access_token": "tok", "expires_in": 1800},
        headers={"X-Cs-Region": "us-2"},
        status=201,
    )
    responses.add(
        responses.GET,
        "https://api.us-2.crowdstrike.com/cloud-security-evaluations/queries/ioms/v1",
        json={"resources": [], "meta": {"pagination": {"total": 0, "offset": 0}}},
        status=200,
    )

    ccm = CCM("crowdstrike_cspm", {"client_id": "id", "client_secret": "secret"})
    df = ccm.collect("iom")

    assert len(df) == 0
    assert len(responses.calls) == 2


@responses.activate
def test_transient_connection_error_is_retried(monkeypatch) -> None:
    monkeypatch.setattr("posture.base.time.sleep", lambda _seconds: None)

    responses.add(
        responses.POST,
        "https://api.crowdstrike.com/oauth2/token",
        json={"access_token": "tok", "expires_in": 1800},
        headers={"X-Cs-Region": "us-1"},
        status=201,
    )
    responses.add(
        responses.GET,
        "https://api.crowdstrike.com/cloud-security-evaluations/queries/ioms/v1",
        body=requests.exceptions.ConnectionError("connection reset"),
    )
    responses.add(
        responses.GET,
        "https://api.crowdstrike.com/cloud-security-evaluations/queries/ioms/v1",
        json={"resources": [], "meta": {"pagination": {"total": 0, "offset": 0}}},
        status=200,
    )

    ccm = CCM("crowdstrike_cspm", {"client_id": "id", "client_secret": "secret"})
    df = ccm.collect("iom")

    assert len(df) == 0
    assert ccm.report("iom")["retries"] == 1


@responses.activate
def test_iom_batches_ids_from_query_then_entities() -> None:
    responses.add(
        responses.POST,
        "https://api.crowdstrike.com/oauth2/token",
        json={"access_token": "tok", "expires_in": 1800},
        headers={"X-Cs-Region": "us-1"},
        status=201,
    )
    responses.add(
        responses.GET,
        "https://api.crowdstrike.com/cloud-security-evaluations/queries/ioms/v1",
        json={
            "resources": ["iom-1"],
            "meta": {"pagination": {"total": 1, "offset": 1}},
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.crowdstrike.com/cloud-security-evaluations/entities/ioms/v1",
        json={
            "resources": [{"id": "iom-1", "cloud_provider": "aws", "severity": "high"}]
        },
        status=200,
    )

    ccm = CCM("crowdstrike_cspm", {"client_id": "id", "client_secret": "secret"})
    df = ccm.collect("iom")

    assert len(df) == 1
    assert df.loc[0, "cloud_provider"] == "aws"
    assert df.loc[0, "severity"] == "high"


@responses.activate
def test_cloud_risks_and_cloud_asset_inventory_use_own_endpoints() -> None:
    responses.add(
        responses.POST,
        "https://api.crowdstrike.com/oauth2/token",
        json={"access_token": "tok", "expires_in": 1800},
        headers={"X-Cs-Region": "us-1"},
        status=201,
    )
    responses.add(
        responses.GET,
        "https://api.crowdstrike.com/cloud-security-risks/combined/cloud-risks/v1",
        json={
            "resources": [{"id": "risk-1", "severity": "critical"}],
            "meta": {"pagination": {"total": 1, "offset": 1}},
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.crowdstrike.com/cloud-security-assets/queries/resources/v1",
        json={
            "resources": ["asset-1"],
            "meta": {"pagination": {"total": 1, "offset": 1}},
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.crowdstrike.com/cloud-security-assets/entities/resources/v1",
        json={"resources": [{"id": "asset-1", "resource_type": "s3_bucket"}]},
        status=200,
    )

    ccm = CCM("crowdstrike_cspm", {"client_id": "id", "client_secret": "secret"})
    cloud_risks_df = ccm.collect("cloud_risks")
    assets_df = ccm.collect("cloud_asset_inventory")

    assert cloud_risks_df.loc[0, "severity"] == "critical"
    assert assets_df.loc[0, "resource_type"] == "s3_bucket"

    query_ids_call = next(
        call
        for call in responses.calls
        if call.request.url.startswith(
            "https://api.crowdstrike.com/cloud-security-assets/queries/resources/v1"
        )
    )
    assert "limit=100" in query_ids_call.request.url


@responses.activate
def test_cloud_asset_inventory_paginates_with_after_token() -> None:
    responses.add(
        responses.POST,
        "https://api.crowdstrike.com/oauth2/token",
        json={"access_token": "tok", "expires_in": 1800},
        headers={"X-Cs-Region": "us-1"},
        status=201,
    )
    # Matches a live tenant's actual response shape: 'total' stays fixed
    # across pages and the next-page cursor is a top-level 'meta.next'
    # value, not nested under 'meta.pagination' — the offset/total path
    # would loop on offset=0 forever (or stop after a page, depending on
    # what's read), so pagination must follow 'meta.next'.
    responses.add(
        responses.GET,
        "https://api.crowdstrike.com/cloud-security-assets/queries/resources/v1",
        json={
            "resources": ["asset-1"],
            "meta": {
                "pagination": {"limit": 100, "total": 2, "offset": 0},
                "next": "cursor-2",
            },
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.crowdstrike.com/cloud-security-assets/entities/resources/v1",
        json={"resources": [{"id": "asset-1", "resource_type": "s3_bucket"}]},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.crowdstrike.com/cloud-security-assets/queries/resources/v1",
        json={
            "resources": ["asset-2"],
            "meta": {"pagination": {"limit": 100, "total": 2}},
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.crowdstrike.com/cloud-security-assets/entities/resources/v1",
        json={"resources": [{"id": "asset-2", "resource_type": "ec2_instance"}]},
        status=200,
    )

    ccm = CCM("crowdstrike_cspm", {"client_id": "id", "client_secret": "secret"})
    assets_df = ccm.collect("cloud_asset_inventory")

    assert sorted(assets_df["id"]) == ["asset-1", "asset-2"]

    query_ids_calls = [
        call
        for call in responses.calls
        if call.request.url.startswith(
            "https://api.crowdstrike.com/cloud-security-assets/queries/resources/v1"
        )
    ]
    assert len(query_ids_calls) == 2
    assert "after=cursor-2" in query_ids_calls[1].request.url
