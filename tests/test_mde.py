import json
from unittest.mock import patch

import responses

from posture import CCM


@responses.activate
def test_machines_pagination() -> None:
    responses.add(
        responses.POST,
        "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token",
        json={"access_token": "tok"},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.security.microsoft.com/api/machines",
        json={"value": [{"id": "machine-1"}]},
        status=200,
    )

    ccm = CCM(
        "mde", {"tenant_id": "tenant-1", "client_id": "id", "client_secret": "secret"}
    )
    df = ccm.collect("machines")

    assert len(df) == 1
    assert ccm.report("machines")["pages"] == 1


@responses.activate
def test_vulnerabilities_follows_skip_based_pagination_across_full_pages() -> None:
    # MDE never returns @odata.nextLink; a full first page ($top records)
    # must be followed by a second request with $skip advanced, not treated
    # as the end of the result set (the bug this test guards against).
    from posture.collectors.mde import _PAGE_SIZE

    page_one = [{"id": f"CVE-{i}"} for i in range(_PAGE_SIZE)]
    page_two = [{"id": "CVE-last"}]

    responses.add(
        responses.POST,
        "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token",
        json={"access_token": "tok"},
        status=200,
    )

    def vulns_callback(request):
        skip = request.params.get("$skip")
        body = {"value": page_one if skip == "0" else page_two}
        return (200, {}, json.dumps(body))

    responses.add_callback(
        responses.GET,
        "https://api.security.microsoft.com/api/vulnerabilities",
        callback=vulns_callback,
        content_type="application/json",
    )

    ccm = CCM(
        "mde", {"tenant_id": "tenant-1", "client_id": "id", "client_secret": "secret"}
    )
    df = ccm.collect("vulnerabilities")

    assert len(df) == _PAGE_SIZE + 1
    assert ccm.report("vulnerabilities")["pages"] == 2


@responses.activate
def test_machine_vulnerabilities_single_page() -> None:
    responses.add(
        responses.POST,
        "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token",
        json={"access_token": "tok"},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.security.microsoft.com/api/machines/SoftwareVulnerabilitiesByMachine",
        json={"value": [{"id": "mv-1", "deviceId": "machine-1", "cveId": "CVE-2026-0001"}]},
        status=200,
    )

    ccm = CCM(
        "mde", {"tenant_id": "tenant-1", "client_id": "id", "client_secret": "secret"}
    )
    df = ccm.collect("machine_vulnerabilities")

    assert len(df) == 1
    assert df.iloc[0]["machine_id"] == "machine-1"
    assert ccm.report("machine_vulnerabilities")["pages"] == 1


@responses.activate
def test_machine_vulnerabilities_follows_odata_next_link() -> None:
    responses.add(
        responses.POST,
        "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token",
        json={"access_token": "tok"},
        status=200,
    )
    next_link = (
        "https://api.security.microsoft.com/api/machines/"
        "SoftwareVulnerabilitiesByMachine?pageSize=50000&$skiptoken=abc"
    )
    responses.add(
        responses.GET,
        "https://api.security.microsoft.com/api/machines/SoftwareVulnerabilitiesByMachine",
        json={
            "value": [{"id": "mv-1", "deviceId": "machine-1"}],
            "@odata.nextLink": next_link,
        },
        status=200,
    )
    responses.add(
        responses.GET,
        next_link,
        json={"value": [{"id": "mv-2", "deviceId": "machine-2"}]},
        status=200,
    )

    ccm = CCM(
        "mde", {"tenant_id": "tenant-1", "client_id": "id", "client_secret": "secret"}
    )
    df = ccm.collect("machine_vulnerabilities")

    assert len(df) == 2
    assert set(df["machine_id"]) == {"machine-1", "machine-2"}
    assert ccm.report("machine_vulnerabilities")["pages"] == 2


@responses.activate
def test_machine_vulnerabilities_retries_on_rate_limit() -> None:
    responses.add(
        responses.POST,
        "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token",
        json={"access_token": "tok"},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.security.microsoft.com/api/machines/SoftwareVulnerabilitiesByMachine",
        status=429,
        headers={"Retry-After": "1"},
    )
    responses.add(
        responses.GET,
        "https://api.security.microsoft.com/api/machines/SoftwareVulnerabilitiesByMachine",
        json={"value": [{"id": "mv-1", "deviceId": "machine-1"}]},
        status=200,
    )

    ccm = CCM(
        "mde", {"tenant_id": "tenant-1", "client_id": "id", "client_secret": "secret"}
    )
    with patch("posture.base.time.sleep"), patch("posture.collectors.mde.time.sleep"):
        df = ccm.collect("machine_vulnerabilities")

    assert len(df) == 1
    assert ccm.report("machine_vulnerabilities")["rate_limited_count"] == 1
