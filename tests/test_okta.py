import responses

from posture import CCM


@responses.activate
def test_users_pagination_follows_link_header() -> None:
    responses.add(
        responses.GET,
        "https://example.okta.com/api/v1/users",
        json=[{"id": "user-1"}],
        headers={
            "Link": '<https://example.okta.com/api/v1/users?after=u1>; rel="next"'
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "https://example.okta.com/api/v1/users?after=u1",
        json=[{"id": "user-2"}],
        status=200,
    )

    ccm = CCM("okta", {"domain": "https://example.okta.com", "token": "tok"})
    df = ccm.collect("users")

    assert list(df["id"]) == ["user-1", "user-2"]
    assert ccm.report("users")["pages"] == 2


@responses.activate
def test_device_users_batches_per_device_and_injects_device_id() -> None:
    responses.add(
        responses.GET,
        "https://example.okta.com/api/v1/devices",
        json=[{"id": "device-1"}, {"id": "device-2"}],
        status=200,
    )
    responses.add(
        responses.GET,
        "https://example.okta.com/api/v1/devices/device-1/users",
        json=[{"user": {"id": "user-1"}}],
        status=200,
    )
    responses.add(
        responses.GET,
        "https://example.okta.com/api/v1/devices/device-2/users",
        json=[],
        status=200,
    )

    ccm = CCM("okta", {"domain": "https://example.okta.com", "token": "tok"})
    df = ccm.collect("device_users")

    assert len(df) == 1
    assert df.loc[0, "device_id"] == "device-1"
    assert df.loc[0, "user_id"] == "user-1"


@responses.activate
def test_401_is_retried_then_propagates_as_incomplete_collection(monkeypatch) -> None:
    from posture.exceptions import IncompleteCollection

    monkeypatch.setattr("posture.base.time.sleep", lambda _seconds: None)

    responses.add(
        responses.GET,
        "https://example.okta.com/api/v1/users",
        json={"errorSummary": "Invalid token"},
        status=401,
    )

    ccm = CCM("okta", {"domain": "https://example.okta.com", "token": "bad-token"})

    try:
        ccm.collect("users")
        assert False, "expected IncompleteCollection"
    except IncompleteCollection:
        pass
