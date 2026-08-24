import responses

from posture import CCM

_BASE = "https://api.acme.nullify.ai"


@responses.activate
def test_repositories_pagination_follows_next_token() -> None:
    responses.add(
        responses.GET,
        f"{_BASE}/admin/repositories",
        json={
            "repositories": [{"id": "r1", "name": "svc-a"}],
            "nextToken": "abc",
        },
        status=200,
    )
    responses.add(
        responses.GET,
        f"{_BASE}/admin/repositories",
        json={
            "repositories": [{"id": "r2", "name": "svc-b"}],
            "nextToken": "",
        },
        status=200,
    )

    ccm = CCM(
        "nullify",
        {"token": "tok", "endpoint": _BASE, "github_owner_id": "1234"},
    )
    df = ccm.collect("repositories")

    assert list(df["id"]) == ["r1", "r2"]
    assert ccm.report("repositories")["pages"] == 2
    assert responses.calls[1].request.params["nextToken"] == "abc"
    assert responses.calls[0].request.params["githubOwnerId"] == "1234"


@responses.activate
def test_sca_events_stops_when_next_token_absent() -> None:
    responses.add(
        responses.GET,
        f"{_BASE}/sca/events",
        json={"events": [{"id": "e1", "severity": "high"}]},
        status=200,
    )

    ccm = CCM(
        "nullify",
        {"token": "tok", "endpoint": _BASE, "github_owner_id": "1234"},
    )
    df = ccm.collect("sca_events")

    assert list(df["id"]) == ["e1"]
    assert ccm.report("sca_events")["pages"] == 1


@responses.activate
def test_sast_events_flattens_repository_and_package_fields() -> None:
    responses.add(
        responses.GET,
        f"{_BASE}/sast/events",
        json={
            "events": [
                {
                    "id": "e1",
                    "ruleId": "py.sql-injection",
                    "severity": "critical",
                    "repository": {"name": "svc-a", "fullName": "acme/svc-a"},
                }
            ]
        },
        status=200,
    )

    ccm = CCM(
        "nullify",
        {"token": "tok", "endpoint": _BASE, "github_owner_id": "1234"},
    )
    df = ccm.collect("sast_events")

    assert df.loc[0, "rule_id"] == "py.sql-injection"
    assert df.loc[0, "repository_full_name"] == "acme/svc-a"


@responses.activate
def test_unauthorized_raises_incomplete_collection() -> None:
    from posture.exceptions import IncompleteCollection

    responses.add(
        responses.GET,
        f"{_BASE}/admin/repositories",
        json={"error": "unauthorized"},
        status=401,
    )

    ccm = CCM(
        "nullify",
        {"token": "bad", "endpoint": _BASE, "github_owner_id": "1234"},
    )

    try:
        ccm.collect("repositories")
        assert False, "expected IncompleteCollection"
    except IncompleteCollection:
        pass
