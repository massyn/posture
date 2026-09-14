"""Trello collector.

Raw ``requests`` against the standard Trello REST API — generic REST with
key/token query-string auth; nothing here needs vendor machinery the base
class can't already generalise.

Resources: ``boards``, ``cards``, ``lists``, ``members``. Cards, lists and
members are not returned by any single paginated endpoint — Trello only
offers them per board (``/boards/{id}/cards``, ``/boards/{id}/lists``,
``/boards/{id}/members``) — so each fans out one request per board via
``Collector._resumable_fanout``, the same shape used for Okta's
``device_users``/Intune's per-device detail lookups. ``cards.id_board``,
``lists.id_board`` and ``members.id_board`` are the join keys back to
``boards.id``; ``cards.id_list`` joins to ``lists.id`` and
``cards.id_members`` joins to ``members.id``.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, ClassVar

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger = logging.getLogger("posture.collectors.trello")

_BASE_URL = "https://api.trello.com/1"
_BOARDS_PATH = "/members/me/boards"
_BOARD_FIELDS = "id,name,url,closed"
_CARD_FIELDS = "id,name,idBoard,idList,idMembers,due,dateLastActivity,shortUrl,closed"
_LIST_FIELDS = "id,idBoard,name,closed"
_MEMBER_FIELDS = "id,idBoard,username,fullName"

# One request per board for `cards` — a handful of workers in parallel cuts
# wall time on accounts with many boards without leaning on Trello's
# per-token rate limit (100 req/10s) hard enough to cause sustained 429s.
_MAX_FANOUT_WORKERS = 5

_BOARD_KWARGS = frozenset({"show_open_only"})
_CARD_KWARGS = frozenset({"board_ids", "show_open_only", "since", "before"})
_LIST_KWARGS = frozenset({"board_ids", "show_open_only"})
_MEMBER_KWARGS = frozenset({"board_ids", "show_open_only"})

MANIFEST: dict[str, dict[str, Any]] = {
    "boards": {
        "endpoint": _BOARDS_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "url": ("url", "str"),
            "closed": ("closed", "bool"),
        },
    },
    "cards": {
        "endpoint": "/boards/{id}/cards",
        "columns": {
            "id": ("id", "str"),
            "id_board": ("idBoard", "str"),
            "name": ("name", "str"),
            "id_list": ("idList", "str"),
            "id_members": ("idMembers", "json"),
            "due": ("due", "datetime"),
            "date_last_activity": ("dateLastActivity", "datetime"),
            "url": ("shortUrl", "str"),
            "closed": ("closed", "bool"),
        },
    },
    "lists": {
        "endpoint": "/boards/{id}/lists",
        "columns": {
            "id": ("id", "str"),
            "id_board": ("idBoard", "str"),
            "name": ("name", "str"),
            "closed": ("closed", "bool"),
        },
    },
    "members": {
        "endpoint": "/boards/{id}/members",
        "columns": {
            "id": ("id", "str"),
            "id_board": ("idBoard", "str"),
            "username": ("username", "str"),
            "full_name": ("fullName", "str"),
        },
    },
}


class TrelloCollector(Collector):
    env_prefix = "TRELLO"
    display_name = "Trello"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {
        "api_key": True,
        "token": True,
        "board": False,
    }

    def _authenticate(self) -> None:
        self._session.headers["Accept"] = "application/json"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        # Neither resource paginates beyond a single call: `boards` fits in
        # one response, and `cards` is itself already the fully-drained
        # result of fanning out one request per board. cursor is always None
        # on the first (only) call and this returns (…, None) to end.
        if cursor is not None:
            return [], None
        if resource == "boards":
            return self._fetch_boards_page(kwargs)
        if resource == "cards":
            return self._fetch_cards_page(kwargs)
        if resource == "lists":
            return self._fetch_lists_page(kwargs)
        if resource == "members":
            return self._fetch_members_page(kwargs)
        raise ValueError(f"Unsupported resource '{resource}'")

    def _fetch_boards_page(
        self, kwargs: dict[str, Any]
    ) -> tuple[list[dict[str, Any]], Any]:
        unknown = set(kwargs) - _BOARD_KWARGS
        if unknown:
            raise ValueError(f"Unsupported kwargs for 'boards': {sorted(unknown)}")
        boards = self._get_boards(
            show_open_only=bool(kwargs.get("show_open_only", False))
        )
        return boards, None

    def _fetch_cards_page(
        self, kwargs: dict[str, Any]
    ) -> tuple[list[dict[str, Any]], Any]:
        unknown = set(kwargs) - _CARD_KWARGS
        if unknown:
            raise ValueError(f"Unsupported kwargs for 'cards': {sorted(unknown)}")

        board_ids = self._resolve_board_ids(kwargs)

        records = self._resumable_fanout(
            "cards", board_ids, self._fetch_cards_for_board, _MAX_FANOUT_WORKERS
        )
        records = self._filter_by_activity(
            records, kwargs.get("since"), kwargs.get("before")
        )
        return records, None

    def _fetch_lists_page(
        self, kwargs: dict[str, Any]
    ) -> tuple[list[dict[str, Any]], Any]:
        unknown = set(kwargs) - _LIST_KWARGS
        if unknown:
            raise ValueError(f"Unsupported kwargs for 'lists': {sorted(unknown)}")

        board_ids = self._resolve_board_ids(kwargs)
        records = self._resumable_fanout(
            "lists", board_ids, self._fetch_lists_for_board, _MAX_FANOUT_WORKERS
        )
        return records, None

    def _fetch_members_page(
        self, kwargs: dict[str, Any]
    ) -> tuple[list[dict[str, Any]], Any]:
        unknown = set(kwargs) - _MEMBER_KWARGS
        if unknown:
            raise ValueError(f"Unsupported kwargs for 'members': {sorted(unknown)}")

        board_ids = self._resolve_board_ids(kwargs)
        records = self._resumable_fanout(
            "members", board_ids, self._fetch_members_for_board, _MAX_FANOUT_WORKERS
        )
        return records, None

    def _resolve_board_ids(self, kwargs: dict[str, Any]) -> list[str]:
        board_ids = kwargs.get("board_ids")
        if board_ids is not None:
            return board_ids
        configured_board = self._config.get("board")
        if configured_board:
            # TRELLO_BOARD / config["board"] sets a default scope so an
            # operator doesn't have to pass board_ids on every call; an
            # explicit board_ids kwarg still wins over it.
            return [configured_board]
        # No explicit board_ids and no configured default: fall back to
        # every board, honouring show_open_only if given. An explicit
        # board_ids is trusted as given regardless of a board's open/closed
        # status — closed-ness is exposed as the `closed` column, not
        # silently filtered.
        return [
            board["id"]
            for board in self._get_boards(
                show_open_only=bool(kwargs.get("show_open_only", False))
            )
        ]

    def _get_boards(self, show_open_only: bool) -> list[dict[str, Any]]:
        response = self._get(_BASE_URL + _BOARDS_PATH, params={"fields": _BOARD_FIELDS})
        boards = response.json()
        if not isinstance(boards, list):
            boards = []
        if show_open_only:
            boards = [board for board in boards if not board.get("closed")]
        return boards

    def _fetch_cards_for_board(self, board_id: str) -> list[dict[str, Any]]:
        response = self._get(
            f"{_BASE_URL}/boards/{board_id}/cards",
            params={"fields": _CARD_FIELDS},
        )
        cards = response.json()
        return cards if isinstance(cards, list) else []

    def _fetch_lists_for_board(self, board_id: str) -> list[dict[str, Any]]:
        response = self._get(
            f"{_BASE_URL}/boards/{board_id}/lists",
            params={"fields": _LIST_FIELDS},
        )
        lists = response.json()
        return lists if isinstance(lists, list) else []

    def _fetch_members_for_board(self, board_id: str) -> list[dict[str, Any]]:
        # Unlike lists/cards, Trello's per-board members response doesn't
        # carry idBoard on each record — it's stamped on here so `members`
        # exposes the same id_board join key as `lists` and `cards`.
        response = self._get(
            f"{_BASE_URL}/boards/{board_id}/members",
            params={"fields": _MEMBER_FIELDS},
        )
        members = response.json()
        if not isinstance(members, list):
            return []
        for member in members:
            member["idBoard"] = board_id
        return members

    @staticmethod
    def _filter_by_activity(
        records: list[dict[str, Any]], since: Any, before: Any
    ) -> list[dict[str, Any]]:
        if since is None and before is None:
            return records
        since_dt = TrelloCollector._to_datetime(since) if since is not None else None
        before_dt = TrelloCollector._to_datetime(before) if before is not None else None

        filtered = []
        for record in records:
            activity = record.get("dateLastActivity")
            if not activity:
                continue
            activity_dt = TrelloCollector._to_datetime(activity)
            if since_dt is not None and activity_dt < since_dt:
                continue
            if before_dt is not None and activity_dt >= before_dt:
                continue
            filtered.append(record)
        return filtered

    @staticmethod
    def _to_datetime(value: Any) -> datetime:
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

    def _get(self, url: str, params: dict[str, Any] | None = None) -> Any:
        request_params = {
            "key": self._config["api_key"],
            "token": self._config["token"],
        }
        if params:
            request_params.update(params)
        response = self._session.get(url, params=request_params, timeout=30)
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitedSignal(
                retry_after=float(retry_after) if retry_after else None
            )
        if response.status_code == 401:
            raise UnauthorizedSignal()
        response.raise_for_status()
        return response
