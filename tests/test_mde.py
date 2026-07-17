import json

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
def test_machine_vulnerabilities_endpoint_is_unpaginated_single_call() -> None:
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
    responses.add(
        responses.GET,
        "https://api.security.microsoft.com/api/machines/machine-1/vulnerabilities",
        json={"value": [{"id": "mv-1"}]},
        status=200,
    )

    ccm = CCM(
        "mde", {"tenant_id": "tenant-1", "client_id": "id", "client_secret": "secret"}
    )
    df = ccm.collect("machine_vulnerabilities")

    assert len(df) == 1
    # exactly two calls: the machines list + one unpaginated per-machine
    # vulnerabilities call, no follow-up request.
    assert len(responses.calls) == 3  # token + machines + machine-1 vulns


@responses.activate
def test_machine_vulnerabilities_fans_out_and_injects_machine_id() -> None:
    responses.add(
        responses.POST,
        "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token",
        json={"access_token": "tok"},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.security.microsoft.com/api/machines",
        json={"value": [{"id": "machine-1"}, {"id": "machine-2"}]},
        status=200,
    )

    def vulns_callback(request):
        machine_id = request.url.rsplit("/", 2)[-2]
        body = {"value": [{"id": f"mv-{machine_id}", "cveId": "CVE-2026-0001"}]}
        return (200, {}, json.dumps(body))

    responses.add_callback(
        responses.GET,
        "https://api.security.microsoft.com/api/machines/machine-1/vulnerabilities",
        callback=vulns_callback,
        content_type="application/json",
    )
    responses.add_callback(
        responses.GET,
        "https://api.security.microsoft.com/api/machines/machine-2/vulnerabilities",
        callback=vulns_callback,
        content_type="application/json",
    )

    ccm = CCM(
        "mde", {"tenant_id": "tenant-1", "client_id": "id", "client_secret": "secret"}
    )
    df = ccm.collect("machine_vulnerabilities")

    assert len(df) == 2
    assert set(df["machine_id"]) == {"machine-1", "machine-2"}
