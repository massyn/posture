import responses

from posture import CCM


@responses.activate
def test_code_scanning_alerts_404_treated_as_empty_not_fatal() -> None:
    """A repo with code scanning disabled 404s on the alerts endpoint —
    that's the absence of a policy, not a collection failure."""
    responses.add(
        responses.GET,
        "https://api.github.com/user/orgs",
        json=[{"id": 1, "login": "acme-corp"}],
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.github.com/orgs/acme-corp/repos",
        json=[{"id": 1, "name": "webapp", "full_name": "acme-corp/webapp"}],
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.github.com/repos/acme-corp/webapp/code-scanning/alerts",
        json={"message": "no analysis found"},
        status=404,
    )

    ccm = CCM("github", {"token": "tok"})
    df = ccm.collect("code_scanning_alerts")

    assert len(df) == 0


@responses.activate
def test_branch_protection_rules_404_treated_as_empty_not_fatal() -> None:
    """Rulesets aren't available on every repo/plan — a 404 here means no
    rules apply, not that the fetch failed."""
    responses.add(
        responses.GET,
        "https://api.github.com/user/orgs",
        json=[{"id": 1, "login": "acme-corp"}],
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.github.com/orgs/acme-corp/repos",
        json=[{"id": 1, "name": "webapp", "full_name": "acme-corp/webapp"}],
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.github.com/repos/acme-corp/webapp/branches",
        json=[{"name": "main", "protected": True, "commit": {"sha": "abc123"}}],
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.github.com/repos/acme-corp/webapp/rules/branches/main",
        json={"message": "Not Found"},
        status=404,
    )

    ccm = CCM("github", {"token": "tok"})
    df = ccm.collect("branch_protection_rules")

    assert len(df) == 0
