import pandas as pd
import responses

from posture import CCM


@responses.activate
def test_profiles_paginates_until_404() -> None:
    responses.add(
        responses.GET,
        "https://api.precise.io/v1/mantelgroup/profiles",
        json=[{"id": "p1", "owner": "a@example.com"}],
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.precise.io/v1/mantelgroup/profiles",
        json=[{"id": "p2", "owner": "b@example.com"}],
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.precise.io/v1/mantelgroup/profiles",
        json={"error": "not found"},
        status=404,
    )

    ccm = CCM("precise", {"token": "tok", "instance": "mantelgroup"})
    df = ccm.collect("profiles")

    assert list(df["profile_id"]) == ["p1", "p2"]
    # 3 requests total: 2 data pages plus the terminal 404, which is still
    # yielded as an (empty) page, so base.py's page count is 3, not 2.
    assert ccm.report("profiles")["pages"] == 3
    pages_requested = [c.request.url.split("page=")[1] for c in responses.calls]
    assert pages_requested == ["1", "2", "3"]


@responses.activate
def test_profiles_terminates_on_empty_list() -> None:
    responses.add(
        responses.GET,
        "https://api.precise.io/v1/mantelgroup/profiles",
        json=[{"id": "p1"}],
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.precise.io/v1/mantelgroup/profiles",
        json=[],
        status=200,
    )

    ccm = CCM("precise", {"token": "tok", "instance": "mantelgroup"})
    df = ccm.collect("profiles")

    assert list(df["profile_id"]) == ["p1"]


@responses.activate
def test_instance_is_substituted_into_url() -> None:
    responses.add(
        responses.GET,
        "https://api.precise.io/v1/acme/profiles",
        json=[],
        status=200,
    )

    ccm = CCM("precise", {"token": "tok", "instance": "acme"})
    ccm.collect("profiles")

    assert len(responses.calls) == 1


_SAMPLE_PROFILE = {
    "id": "p1",
    "owner": "a@example.com",
    "path": "/a/p1",
    "about": {"name": "Aaron Doggett", "title": "Principal Consultant"},
    "network": [{"type": "Linkedin", "url": "https://linkedin.com/in/a"}],
    "education": [{"place": "ECU", "period": "2002", "description": "BSc"}],
    "experience": [
        {
            "place": "Mantel Group",
            "period": "2024 - Current",
            "role": "Principal Consultant",
            "description": "...",
            "industry": ["16"],
            "projects": [{"title": "IRAP Assessment", "industry": ["16"]}],
        }
    ],
    "skills": [{"name": "iOS Development", "level": 5}],
    "certifications": [
        {
            "name": "CISSP",
            "org_certification_id": "288",
            "valid_from": "01/07/2008",
            "valid_to": "01/07/2028",
        }
    ],
    "conferences": [{"place": "WACTF", "title": "Keynote"}],
    "tracks": [{"category": "Comms", "name": "Writing", "level": 4}],
    "completeness_score": 85,
    "created_at": "2024-07-16T03:04:57.235Z",
}


@responses.activate
def test_profiles_carries_only_scalar_fields() -> None:
    responses.add(
        responses.GET,
        "https://api.precise.io/v1/mantelgroup/profiles",
        json=[_SAMPLE_PROFILE],
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.precise.io/v1/mantelgroup/profiles",
        json=[],
        status=200,
    )

    ccm = CCM("precise", {"token": "tok", "instance": "mantelgroup"})
    df = ccm.collect("profiles")

    assert df.loc[0, "about_name"] == "Aaron Doggett"
    assert df.loc[0, "completeness_score"] == 85
    assert df["created_at"].dtype == "datetime64[us, UTC]"
    assert "skills" not in df.columns
    assert "certifications" not in df.columns


@responses.activate
def test_derived_resources_carry_parent_profile_id_and_owner() -> None:
    responses.add(
        responses.GET,
        "https://api.precise.io/v1/mantelgroup/profiles",
        json=[_SAMPLE_PROFILE],
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.precise.io/v1/mantelgroup/profiles",
        json=[],
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.precise.io/v1/mantelgroup/profiles",
        json=[_SAMPLE_PROFILE],
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.precise.io/v1/mantelgroup/profiles",
        json=[],
        status=200,
    )

    ccm = CCM("precise", {"token": "tok", "instance": "mantelgroup"})

    skills = ccm.collect("profile_skills")
    assert skills.loc[0, "profile_id"] == "p1"
    assert skills.loc[0, "owner_email"] == "a@example.com"
    assert skills.loc[0, "name"] == "iOS Development"

    certifications = ccm.collect("profile_certifications")
    assert certifications.loc[0, "org_certification_id"] == "288"
    # Day-first "01/07/2008" must parse as 1 July 2008, not 7 January (the
    # default month-first guess) — see the manifest's explicit format hint.
    assert certifications.loc[0, "valid_from"] == pd.Timestamp("2008-07-01", tz="UTC")


@responses.activate
def test_profile_experience_keeps_nested_projects_as_json() -> None:
    responses.add(
        responses.GET,
        "https://api.precise.io/v1/mantelgroup/profiles",
        json=[_SAMPLE_PROFILE],
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.precise.io/v1/mantelgroup/profiles",
        json=[],
        status=200,
    )

    ccm = CCM("precise", {"token": "tok", "instance": "mantelgroup"})
    df = ccm.collect("profile_experience")

    assert df.loc[0, "role"] == "Principal Consultant"
    assert "IRAP Assessment" in df.loc[0, "projects"]
    assert "16" in df.loc[0, "industry"]


@responses.activate
def test_401_propagates_as_incomplete_collection(monkeypatch) -> None:
    from posture.exceptions import IncompleteCollection

    monkeypatch.setattr("posture.base.time.sleep", lambda _seconds: None)

    responses.add(
        responses.GET,
        "https://api.precise.io/v1/mantelgroup/profiles",
        json={"error": "unauthorized"},
        status=401,
    )

    ccm = CCM("precise", {"token": "bad-token", "instance": "mantelgroup"})

    try:
        ccm.collect("profiles")
        assert False, "expected IncompleteCollection"
    except IncompleteCollection:
        pass
