import responses

from posture import CCM


@responses.activate
def test_databases_pagination_follows_next_url() -> None:
    responses.add(
        responses.GET,
        "https://api.production.selectstar.com/v1/databases/",
        json={
            "count": 2,
            "next": "https://api.production.selectstar.com/v1/databases/?page=2",
            "previous": None,
            "results": [{"id": "d1", "name": "warehouse"}],
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.production.selectstar.com/v1/databases/?page=2",
        json={
            "count": 2,
            "next": None,
            "previous": "https://api.production.selectstar.com/v1/databases/",
            "results": [{"id": "d2", "name": "analytics"}],
        },
        status=200,
    )

    ccm = CCM("select_star", {"token": "tok"})
    df = ccm.collect("databases")

    assert list(df["id"]) == ["d1", "d2"]
    assert ccm.report("databases")["pages"] == 2


@responses.activate
def test_tables_flattens_nested_database() -> None:
    responses.add(
        responses.GET,
        "https://api.production.selectstar.com/v1/tables/",
        json={
            "count": 1,
            "next": None,
            "previous": None,
            "results": [
                {
                    "id": "t1",
                    "name": "orders",
                    "database": {"id": "d1", "name": "warehouse"},
                    "row_count": 100,
                }
            ],
        },
        status=200,
    )

    ccm = CCM("select_star", {"token": "tok"})
    df = ccm.collect("tables")

    assert df.loc[0, "id"] == "t1"
    assert df.loc[0, "database_id"] == "d1"
    assert df.loc[0, "database_name"] == "warehouse"
    assert df.loc[0, "row_count"] == 100


@responses.activate
def test_unauthorized_raises_incomplete_collection() -> None:
    from posture.exceptions import IncompleteCollection

    responses.add(
        responses.GET,
        "https://api.production.selectstar.com/v1/databases/",
        json={"detail": "invalid token"},
        status=401,
    )

    ccm = CCM("select_star", {"token": "bad"})

    try:
        ccm.collect("databases")
        assert False, "expected IncompleteCollection"
    except IncompleteCollection:
        pass
