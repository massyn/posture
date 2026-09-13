import json
from pathlib import Path

import pandas as pd

from posture.collectors.trello import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "trello"

BOARDS_MANIFEST = MANIFEST["boards"]
CARDS_MANIFEST = MANIFEST["cards"]


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_boards_page() -> None:
    df = parse(_load("boards_page.json"), BOARDS_MANIFEST, resource="boards")

    assert len(df) == 2
    assert list(df["id"]) == ["board-1", "board-2"]
    assert bool(df.loc[0, "closed"]) is False
    assert bool(df.loc[1, "closed"]) is True


def test_cards_page() -> None:
    df = parse(_load("cards_page.json"), CARDS_MANIFEST, resource="cards")

    assert len(df) == 2
    assert df.loc[0, "id_board"] == "board-1"
    assert df.loc[0, "id_members"] == '["member-1", "member-2"]'
    assert df["due"].dtype == "datetime64[us, UTC]"
    assert df["date_last_activity"].dtype == "datetime64[us, UTC]"
    assert pd.isna(df.loc[1, "due"])  # absent in fixture
    assert bool(df.loc[1, "closed"]) is True
