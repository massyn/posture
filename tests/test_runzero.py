import responses

from posture import CCM


@responses.activate
def test_assets_is_a_single_unpaginated_call() -> None:
    responses.add(
        responses.GET,
        "https://console.runzero.com/api/v1.0/export/org/assets.json",
        json=[
            {"id": "a1", "name": "host-1", "alive": True},
            {"id": "a2", "name": "host-2", "alive": False},
        ],
        status=200,
    )

    ccm = CCM("runzero", {"token": "tok"})
    df = ccm.collect("assets")

    assert list(df["id"]) == ["a1", "a2"]
    assert list(df["alive"]) == [True, False]
    assert ccm.report("assets")["pages"] == 1


@responses.activate
def test_empty_export_returns_declared_columns_zero_rows() -> None:
    responses.add(
        responses.GET,
        "https://console.runzero.com/api/v1.0/export/org/assets.json",
        json=[],
        status=200,
    )

    ccm = CCM("runzero", {"token": "tok"})
    df = ccm.collect("assets")

    assert len(df) == 0
    assert "id" in df.columns


@responses.activate
def test_endpoint_override_is_normalized_and_used() -> None:
    responses.add(
        responses.GET,
        "https://runzero.internal.example.com/api/v1.0/export/org/assets.json",
        json=[{"id": "a1"}],
        status=200,
    )

    ccm = CCM(
        "runzero",
        {"token": "tok", "endpoint": "runzero.internal.example.com/api/v1.0"},
    )
    df = ccm.collect("assets")

    assert list(df["id"]) == ["a1"]


@responses.activate
def test_unauthorized_raises_incomplete_collection() -> None:
    from posture.exceptions import IncompleteCollection

    responses.add(
        responses.GET,
        "https://console.runzero.com/api/v1.0/export/org/assets.json",
        json={"error": "invalid token"},
        status=401,
    )

    ccm = CCM("runzero", {"token": "bad"})

    try:
        ccm.collect("assets")
        assert False, "expected IncompleteCollection"
    except IncompleteCollection:
        pass
