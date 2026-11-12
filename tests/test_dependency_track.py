import pytest
import responses
from responses import matchers

from posture import CCM
from posture.collectors import dependency_track

BASE = "https://dtrack.example.com/api/v1"
CONFIG = {"api_key": "key", "endpoint": "dtrack.example.com/"}


@pytest.fixture
def small_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dependency_track, "_PAGE_SIZE", 2)


@responses.activate
def test_projects_drain_until_short_page(small_pages: None) -> None:
    responses.add(
        responses.GET,
        f"{BASE}/project",
        match=[matchers.query_param_matcher({"offset": "0", "limit": "2"})],
        json=[{"uuid": "p1"}, {"uuid": "p2"}],
        headers={"X-Total-Count": "3"},
    )
    responses.add(
        responses.GET,
        f"{BASE}/project",
        match=[matchers.query_param_matcher({"offset": "2", "limit": "2"})],
        json=[{"uuid": "p3"}],
        headers={"X-Total-Count": "3"},
    )

    ccm = CCM("dependency_track", CONFIG)
    df = ccm.collect("projects")

    assert list(df["project_uuid"]) == ["p1", "p2", "p3"]
    assert ccm.report("projects")["pages"] == 2
    assert responses.calls[0].request.headers["X-Api-Key"] == "key"


@responses.activate
def test_project_components_fans_out_and_skips_deleted_project(
    small_pages: None,
) -> None:
    responses.add(
        responses.GET,
        f"{BASE}/project",
        json=[{"uuid": "p1"}, {"uuid": "gone"}],
        headers={"X-Total-Count": "2"},
    )
    for offset, body in ((0, [{"uuid": "c1"}, {"uuid": "c2"}]), (2, [{"uuid": "c3"}])):
        responses.add(
            responses.GET,
            f"{BASE}/component/project/p1",
            match=[matchers.query_param_matcher({"offset": str(offset), "limit": "2"})],
            json=body,
            headers={"X-Total-Count": "3"},
        )
    responses.add(responses.GET, f"{BASE}/component/project/gone", status=404)

    ccm = CCM("dependency_track", CONFIG)
    df = ccm.collect("project_components")

    assert list(df["component_uuid"]) == ["c1", "c2", "c3"]
    assert list(df["project_uuid"]) == ["p1", "p1", "p1"]


@responses.activate
def test_project_findings_include_suppressed_unless_overridden(
    small_pages: None,
) -> None:
    responses.add(
        responses.GET,
        f"{BASE}/finding/project/p1",
        match=[
            matchers.query_param_matcher(
                {"suppressed": "false", "offset": "0", "limit": "2"}
            )
        ],
        json=[{"vulnerability": {"vulnId": "CVE-1"}}],
        headers={"X-Total-Count": "1"},
    )
    responses.add(
        responses.GET,
        f"{BASE}/finding/project/p1",
        match=[
            matchers.query_param_matcher(
                {"suppressed": "true", "offset": "0", "limit": "2"}
            )
        ],
        json=[
            {"vulnerability": {"vulnId": "CVE-1"}},
            {"vulnerability": {"vulnId": "CVE-2"}},
            {"vulnerability": {"vulnId": "CVE-3"}},
        ],
        headers={"X-Total-Count": "3"},
    )

    ccm = CCM("dependency_track", CONFIG)
    # The server ignored paging (3 rows on a page of 2): no page 2 request.
    df = ccm.collect("project_findings", project_uuids=["p1"])
    assert list(df["vuln_id"]) == ["CVE-1", "CVE-2", "CVE-3"]

    df = ccm.collect("project_findings", project_uuids=["p1"], suppressed="false")
    assert list(df["vuln_id"]) == ["CVE-1"]
