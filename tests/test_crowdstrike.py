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
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.us-2.crowdstrike.com/devices/queries/devices/v1",
        json={"resources": [], "meta": {"pagination": {"total": 0, "offset": 0}}},
        status=200,
    )

    ccm = CCM("crowdstrike", {"client_id": "id", "client_secret": "secret"})
    df = ccm.collect("hosts")

    assert len(df) == 0
    # only two calls were registered (us-2 token + us-2 devices query); if the
    # collector had stayed on api.crowdstrike.com for the devices call, responses
    # would raise ConnectionError for the unregistered us-1 devices URL.
    assert len(responses.calls) == 2


@responses.activate
def test_transient_connection_error_is_retried(monkeypatch) -> None:
    monkeypatch.setattr("posture.base.time.sleep", lambda _seconds: None)

    responses.add(
        responses.POST,
        "https://api.crowdstrike.com/oauth2/token",
        json={"access_token": "tok", "expires_in": 1800},
        headers={"X-Cs-Region": "us-1"},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.crowdstrike.com/devices/queries/devices/v1",
        body=requests.exceptions.ConnectionError("connection reset"),
    )
    responses.add(
        responses.GET,
        "https://api.crowdstrike.com/devices/queries/devices/v1",
        json={"resources": [], "meta": {"pagination": {"total": 0, "offset": 0}}},
        status=200,
    )

    ccm = CCM("crowdstrike", {"client_id": "id", "client_secret": "secret"})
    df = ccm.collect("hosts")

    assert len(df) == 0
    assert ccm.report("hosts")["retries"] == 1


@responses.activate
def test_vulnerabilities_pagination_follows_after_cursor() -> None:
    responses.add(
        responses.POST,
        "https://api.crowdstrike.com/oauth2/token",
        json={"access_token": "tok", "expires_in": 1800},
        headers={"X-Cs-Region": "us-1"},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.crowdstrike.com/spotlight/combined/vulnerabilities/v1",
        json={
            "resources": [{"id": "vuln-1", "cve": {"id": "CVE-2026-0001"}}],
            "meta": {"pagination": {"total": 2, "after": "cursor-2"}},
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.crowdstrike.com/spotlight/combined/vulnerabilities/v1",
        json={
            "resources": [{"id": "vuln-2", "cve": {"id": "CVE-2026-0002"}}],
            "meta": {"pagination": {"total": 2, "after": ""}},
        },
        status=200,
    )

    ccm = CCM("crowdstrike", {"client_id": "id", "client_secret": "secret"})
    df = ccm.collect("vulnerabilities")

    assert list(df["cve_id"]) == ["CVE-2026-0001", "CVE-2026-0002"]
    assert ccm.report("vulnerabilities")["pages"] == 2


@responses.activate
def test_zero_trust_assessment_batches_ids_from_device_query() -> None:
    responses.add(
        responses.POST,
        "https://api.crowdstrike.com/oauth2/token",
        json={"access_token": "tok", "expires_in": 1800},
        headers={"X-Cs-Region": "us-1"},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.crowdstrike.com/devices/queries/devices/v1",
        json={
            "resources": ["dev-1"],
            "meta": {"pagination": {"total": 1, "offset": 1}},
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.crowdstrike.com/zero-trust-assessment/entities/assessments/v1",
        json={"resources": [{"aid": "dev-1", "assessment": {"overall": 90}}]},
        status=200,
    )

    ccm = CCM("crowdstrike", {"client_id": "id", "client_secret": "secret"})
    df = ccm.collect("zero_trust_assessment")

    assert len(df) == 1
    assert df.loc[0, "assessment_overall"] == 90


@responses.activate
def test_report_works_for_derived_resource_name_not_just_source() -> None:
    responses.add(
        responses.POST,
        "https://api.crowdstrike.com/oauth2/token",
        json={"access_token": "tok", "expires_in": 1800},
        headers={"X-Cs-Region": "us-1"},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.crowdstrike.com/devices/queries/devices/v1",
        json={
            "resources": ["dev-1"],
            "meta": {"pagination": {"total": 1, "offset": 1}},
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.crowdstrike.com/zero-trust-assessment/entities/assessments/v1",
        json={
            "resources": [
                {
                    "aid": "dev-1",
                    "assessment_items": {
                        "os_signals": [{"signal_id": "sig-1"}],
                        "sensor_signals": [],
                    },
                }
            ]
        },
        status=200,
    )

    ccm = CCM("crowdstrike", {"client_id": "id", "client_secret": "secret"})
    df = ccm.collect("zero_trust_assessment_os_signals")

    assert len(df) == 1
    # report() must work for the derived resource's own name, not just the
    # underlying "zero_trust_assessment" it was fetched from.
    report = ccm.report("zero_trust_assessment_os_signals")
    assert report["resource"] == "zero_trust_assessment"
    assert report["pages"] == 1
