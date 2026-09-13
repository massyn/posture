import responses

from posture import CCM


@responses.activate
def test_boards_returns_open_and_closed_by_default() -> None:
    responses.add(
        responses.GET,
        "https://api.trello.com/1/members/me/boards",
        json=[
            {"id": "board-1", "name": "Engineering", "url": "u1", "closed": False},
            {"id": "board-2", "name": "Old", "url": "u2", "closed": True},
        ],
        status=200,
    )

    ccm = CCM("trello", {"api_key": "key", "token": "tok"})
    df = ccm.collect("boards")

    assert sorted(df["id"]) == ["board-1", "board-2"]


@responses.activate
def test_boards_show_open_only_filters_closed() -> None:
    responses.add(
        responses.GET,
        "https://api.trello.com/1/members/me/boards",
        json=[
            {"id": "board-1", "name": "Engineering", "url": "u1", "closed": False},
            {"id": "board-2", "name": "Old", "url": "u2", "closed": True},
        ],
        status=200,
    )

    ccm = CCM("trello", {"api_key": "key", "token": "tok"})
    df = ccm.collect("boards", show_open_only=True)

    assert list(df["id"]) == ["board-1"]


@responses.activate
def test_cards_fans_out_across_all_boards_by_default() -> None:
    responses.add(
        responses.GET,
        "https://api.trello.com/1/members/me/boards",
        json=[
            {"id": "board-1", "name": "A", "url": "u1", "closed": False},
            {"id": "board-2", "name": "B", "url": "u2", "closed": False},
        ],
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.trello.com/1/boards/board-1/cards",
        json=[{"id": "card-1", "idBoard": "board-1", "name": "Card 1"}],
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.trello.com/1/boards/board-2/cards",
        json=[{"id": "card-2", "idBoard": "board-2", "name": "Card 2"}],
        status=200,
    )

    ccm = CCM("trello", {"api_key": "key", "token": "tok"})
    df = ccm.collect("cards")

    assert sorted(df["id"]) == ["card-1", "card-2"]


@responses.activate
def test_cards_board_ids_trusts_caller_even_when_closed() -> None:
    responses.add(
        responses.GET,
        "https://api.trello.com/1/boards/board-2/cards",
        json=[{"id": "card-2", "idBoard": "board-2", "name": "Card 2", "closed": True}],
        status=200,
    )

    ccm = CCM("trello", {"api_key": "key", "token": "tok"})
    df = ccm.collect("cards", board_ids=["board-2"])

    assert list(df["id"]) == ["card-2"]


@responses.activate
def test_cards_uses_configured_default_board() -> None:
    responses.add(
        responses.GET,
        "https://api.trello.com/1/boards/board-1/cards",
        json=[{"id": "card-1", "idBoard": "board-1", "name": "Card 1"}],
        status=200,
    )

    ccm = CCM("trello", {"api_key": "key", "token": "tok", "board": "board-1"})
    df = ccm.collect("cards")

    assert list(df["id"]) == ["card-1"]


@responses.activate
def test_cards_board_ids_kwarg_overrides_configured_board() -> None:
    responses.add(
        responses.GET,
        "https://api.trello.com/1/boards/board-2/cards",
        json=[{"id": "card-2", "idBoard": "board-2", "name": "Card 2"}],
        status=200,
    )

    ccm = CCM("trello", {"api_key": "key", "token": "tok", "board": "board-1"})
    df = ccm.collect("cards", board_ids=["board-2"])

    assert list(df["id"]) == ["card-2"]


@responses.activate
def test_cards_since_filters_out_stale_activity() -> None:
    responses.add(
        responses.GET,
        "https://api.trello.com/1/boards/board-1/cards",
        json=[
            {
                "id": "card-1",
                "idBoard": "board-1",
                "name": "Fresh",
                "dateLastActivity": "2026-09-10T00:00:00.000Z",
            },
            {
                "id": "card-2",
                "idBoard": "board-1",
                "name": "Stale",
                "dateLastActivity": "2026-01-01T00:00:00.000Z",
            },
        ],
        status=200,
    )

    ccm = CCM("trello", {"api_key": "key", "token": "tok"})
    df = ccm.collect("cards", board_ids=["board-1"], since="2026-06-01T00:00:00Z")

    assert list(df["id"]) == ["card-1"]
