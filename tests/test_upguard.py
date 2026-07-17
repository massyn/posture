import json

import responses

from posture import CCM


@responses.activate
def test_vendors_pagination_stops_on_partial_page() -> None:
    responses.add(
        responses.GET,
        "https://au.cyber-risk.upguard.com/api/public/vendors",
        json={"vendors": [{"id": "vendor-1", "primary_hostname": "acme.example.com"}]},
        status=200,
    )

    ccm = CCM("upguard", {"api_key": "key"})
    df = ccm.collect("vendors")

    assert len(df) == 1
    assert ccm.report("vendors")["pages"] == 1


@responses.activate
def test_organisation_is_a_single_object_not_a_list() -> None:
    responses.add(
        responses.GET,
        "https://au.cyber-risk.upguard.com/api/public/organisation",
        json={"id": "org-1", "name": "Our Org"},
        status=200,
    )

    ccm = CCM("upguard", {"api_key": "key"})
    df = ccm.collect("organisation")

    assert len(df) == 1
    assert df.loc[0, "organisation_id"] == "org-1"
    assert ccm.report("organisation")["pages"] == 1


@responses.activate
def test_vendor_risks_fans_out_across_vendors_and_tags_hostname() -> None:
    responses.add(
        responses.GET,
        "https://au.cyber-risk.upguard.com/api/public/vendors",
        json={
            "vendors": [
                {"id": "v1", "primary_hostname": "acme.example.com"},
                {"id": "v2", "primary_hostname": "beta.example.com"},
            ]
        },
        status=200,
    )

    def risks_callback(request):
        hostname = request.params.get("primary_hostname")
        body = {"risks": [{"id": f"risk-{hostname}", "finding": "test"}]}
        return (200, {}, json.dumps(body))

    responses.add_callback(
        responses.GET,
        "https://au.cyber-risk.upguard.com/api/public/risks/vendors",
        callback=risks_callback,
        content_type="application/json",
    )

    ccm = CCM("upguard", {"api_key": "key"})
    df = ccm.collect("vendor_risks")

    assert len(df) == 2
    assert set(df["requested_primary_hostname"]) == {
        "acme.example.com",
        "beta.example.com",
    }


@responses.activate
def test_vendor_risks_isolates_a_single_vendors_429_without_restarting_the_batch(
    monkeypatch,
) -> None:
    monkeypatch.setattr("posture.collectors.upguard.time.sleep", lambda _s: None)

    vendors_call_count = 0

    def vendors_callback(_request):
        nonlocal vendors_call_count
        vendors_call_count += 1
        body = {
            "vendors": [
                {"id": "v1", "primary_hostname": "flaky.example.com"},
                {"id": "v2", "primary_hostname": "healthy.example.com"},
            ]
        }
        return (200, {}, json.dumps(body))

    responses.add_callback(
        responses.GET,
        "https://au.cyber-risk.upguard.com/api/public/vendors",
        callback=vendors_callback,
        content_type="application/json",
    )

    flaky_attempts = 0

    def risks_callback(request):
        nonlocal flaky_attempts
        hostname = request.params.get("primary_hostname")
        if hostname == "flaky.example.com":
            flaky_attempts += 1
            if flaky_attempts < 3:
                return (429, {}, json.dumps({}))
        body = {"risks": [{"id": f"risk-{hostname}", "finding": "test"}]}
        return (200, {}, json.dumps(body))

    responses.add_callback(
        responses.GET,
        "https://au.cyber-risk.upguard.com/api/public/risks/vendors",
        callback=risks_callback,
        content_type="application/json",
    )

    ccm = CCM("upguard", {"api_key": "key"})
    df = ccm.collect("vendor_risks")

    # the vendor list must be fetched exactly once — a per-vendor 429 must
    # not force base.py to restart the entire fan-out (re-fetching vendors
    # and every other vendor's already-successful work) from scratch.
    assert vendors_call_count == 1
    assert len(df) == 2
    assert set(df["requested_primary_hostname"]) == {
        "flaky.example.com",
        "healthy.example.com",
    }
