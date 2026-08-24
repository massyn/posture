import responses

from posture import CCM


@responses.activate
def test_workers_scripts_dedupes_accounts_from_zones() -> None:
    responses.add(
        responses.GET,
        "https://api.cloudflare.com/client/v4/zones",
        json={
            "success": True,
            "result": [
                {"id": "zone-1", "name": "example.com", "account": {"id": "acct-1"}},
                {"id": "zone-2", "name": "example.org", "account": {"id": "acct-1"}},
            ],
            "result_info": {"page": 1, "total_pages": 1},
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.cloudflare.com/client/v4/accounts/acct-1/workers/scripts",
        json={
            "success": True,
            "result": [{"id": "api-worker"}],
            "result_info": {"page": 1, "total_pages": 1},
        },
        status=200,
    )

    ccm = CCM("cloudflare", {"api_token": "tok"})
    df = ccm.collect("workers_scripts")

    assert len(df) == 1
    assert df.loc[0, "account_id"] == "acct-1"
    # Two zones share one account — the account is only fetched once.
    scripts_calls = [c for c in responses.calls if "workers/scripts" in c.request.url]
    assert len(scripts_calls) == 1


@responses.activate
def test_workers_routes_fans_out_per_zone() -> None:
    responses.add(
        responses.GET,
        "https://api.cloudflare.com/client/v4/zones",
        json={
            "success": True,
            "result": [{"id": "zone-1", "name": "example.com"}],
            "result_info": {"page": 1, "total_pages": 1},
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.cloudflare.com/client/v4/zones/zone-1/workers/routes",
        json={
            "success": True,
            "result": [{"id": "route-1", "pattern": "example.com/*", "script": "w"}],
            "result_info": {"page": 1, "total_pages": 1},
        },
        status=200,
    )

    ccm = CCM("cloudflare", {"api_token": "tok"})
    df = ccm.collect("workers_routes")

    assert len(df) == 1
    assert df.loc[0, "zone_id"] == "zone-1"
    assert df.loc[0, "zone_name"] == "example.com"
