"""Miro collector.

Raw ``requests`` against Miro's REST API v2 (``https://api.miro.com``), no
vendor SDK. Auth is a static OAuth2 access token in the ``Authorization:
Bearer`` header — Miro has **no client-credentials grant**, so the token
must be minted out-of-band (the "Install app and get OAuth token" button in
the Miro Developer console, or an ``authorization_code`` exchange) and
supplied as ``access_token`` config (env ``MIRO_ACCESS_TOKEN``). The
``client_id``/``client_secret`` of the
app are not used by this collector; only the resulting access token is.

The organization id every ``/v2/orgs/{org_id}/...`` endpoint needs is
**discovered**, not configured: ``_authenticate`` calls
``GET /v1/oauth-token`` once and caches ``organization.id`` on the instance
— the same "discover, then route" shape as DNSimple's account-id lookup or
Crowdstrike's region header.

Resources:

- ``boards`` — one row per board. ``GET /v2/boards``, offset/limit
  pagination. The board object's ``policy.sharingPolicy`` /
  ``policy.permissionsPolicy`` are flattened into ``sharing_*`` / ``perm_*``
  columns — these are the posture-relevant exposure signals (a board with
  ``sharing_access`` = ``view``/``comment``/``edit`` or
  ``sharing_organization_access`` != ``private`` is reachable beyond its
  explicit members).
- ``board_members`` — one row per (board, member): the per-board role
  grant (``viewer`` / ``commenter`` / ``editor`` / ``coowner`` /
  ``owner``). A per-board fan-out of ``GET /v2/boards/{id}/members``
  (``requires: "boards"``), offset/limit per board.
- ``org_members`` — one row per organization member: email, org role,
  license, ``active`` flag, and ``last_activity_at`` (dormant-account and
  over-licensing signal). ``GET /v2/orgs/{org_id}/members``, cursor
  pagination. **Enterprise plan + Company Admin token + ``organizations:read``
  scope.**
- ``teams`` — one row per team. ``GET /v2/orgs/{org_id}/teams``, cursor
  pagination. **Enterprise + ``organizations:teams:read``.**
- ``team_members`` — one row per (team, member): team-level role. A
  per-team fan-out of ``GET /v2/orgs/{org_id}/teams/{team_id}/members``
  (``requires: "teams"``), cursor pagination per team. **Enterprise +
  ``organizations:teams:read``.**
- ``audit_logs`` — one row per audit event (permission changes, exports,
  board deletes, sign-ins, ...). ``GET /v2/audit/logs``, cursor
  pagination. The endpoint **requires** a ``createdAfter``/``createdBefore``
  window; this collector defaults it to the trailing 30 days (Miro only
  retains 90 days via the API regardless). Override with one of
  ``window_hours=<n>`` (synthetic) or ``created_after``/``created_before``
  (epoch or ISO 8601 — the since-instant form for a delta extractor);
  passing both forms raises ``ValueError``. **Enterprise + ``auditlogs:read``.**
- ``board_classifications`` — one row per classified board: the applied
  data-classification label (``name``, ``color``, ``sharing_recommendation``).
  A per-board fan-out of
  ``GET /v2/orgs/{org_id}/teams/{team_id}/boards/{board_id}/data-classification``
  (``requires: "boards"``, ``team_id`` taken from each board's own
  ``team.id``). A board with no label returns 404 and is simply absent from
  the result — grain is sacred, no null-padded row. **Enterprise + Data
  Classification add-on + Company Admin.**

A 403 ``insufficientPermissions`` (missing scope or non-Enterprise plan)
raises ``PermissionDeniedSignal`` — it is a credential/plan problem, not a
transient failure, so it fails fast with Miro's "Required scopes: ..."
message intact rather than being retried.

**Live-verified** against a non-Enterprise team (2026-08-29): ``boards``
(including the full ``policy`` block) and ``board_members``. The five
org-scoped resources (``org_members``, ``teams``, ``team_members``,
``audit_logs``, ``board_classifications``) were built from Miro's published
OpenAPI reference — the test token lacked the Enterprise scopes to reach
them — same "not live-verified" caveat tier as ``wiz.py``/``appomni.py``.
Verify field names/nesting against a real Enterprise tenant before relying
on those five.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar

from posture.base import (
    Collector,
    PermissionDeniedSignal,
    RateLimitedSignal,
    UnauthorizedSignal,
)

logger = logging.getLogger("posture.collectors.miro")

_DEFAULT_BASE_URL = "https://api.miro.com"
_PAGE_SIZE = 50
_DEFAULT_AUDIT_WINDOW_HOURS = 30 * 24
_DEFAULT_FANOUT_MAX_WORKERS = 10
_MIRO_DATETIME = "%Y-%m-%dT%H:%M:%S.000Z"

MANIFEST: dict[str, dict[str, Any]] = {
    "boards": {
        "endpoint": "/v2/boards",
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "description": ("description", "str"),
            "team_id": ("team.id", "str"),
            "team_name": ("team.name", "str"),
            "project_id": ("project.id", "str"),
            "view_link": ("viewLink", "str"),
            "owner_id": ("owner.id", "str"),
            "owner_name": ("owner.name", "str"),
            "created_at": ("createdAt", "datetime"),
            "created_by_id": ("createdBy.id", "str"),
            "created_by_name": ("createdBy.name", "str"),
            "modified_at": ("modifiedAt", "datetime"),
            "modified_by_id": ("modifiedBy.id", "str"),
            "last_opened_at": ("lastOpenedAt", "datetime"),
            "sharing_access": ("policy.sharingPolicy.access", "str"),
            "sharing_organization_access": (
                "policy.sharingPolicy.organizationAccess",
                "str",
            ),
            "sharing_team_access": ("policy.sharingPolicy.teamAccess", "str"),
            "sharing_invite_access": (
                "policy.sharingPolicy.inviteToAccountAndBoardLinkAccess",
                "str",
            ),
            "sharing_password_required": (
                "policy.sharingPolicy.accessPasswordRequired",
                "bool",
            ),
            "perm_collaboration_tools_start_access": (
                "policy.permissionsPolicy.collaborationToolsStartAccess",
                "str",
            ),
            "perm_copy_access": ("policy.permissionsPolicy.copyAccess", "str"),
            "perm_sharing_access": ("policy.permissionsPolicy.sharingAccess", "str"),
        },
    },
    "board_members": {
        "requires": "boards",
        "endpoint": "/v2/boards/{board_id}/members",
        "columns": {
            "board_id": ("_board_id", "str"),
            "board_name": ("_board_name", "str"),
            "id": ("id", "str"),
            "name": ("name", "str"),
            "role": ("role", "str"),
        },
    },
    "org_members": {
        "endpoint": "/v2/orgs/{org_id}/members",
        "columns": {
            "id": ("id", "str"),
            "email": ("email", "str"),
            "active": ("active", "bool"),
            "license": ("license", "str"),
            "role": ("role", "str"),
            "last_activity_at": ("lastActivityAt", "datetime"),
            "license_assigned_at": ("licenseAssignedAt", "datetime"),
            "admin_roles": ("adminRoles", "json"),
        },
    },
    "teams": {
        "endpoint": "/v2/orgs/{org_id}/teams",
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
        },
    },
    "team_members": {
        "requires": "teams",
        "endpoint": "/v2/orgs/{org_id}/teams/{team_id}/members",
        "columns": {
            "team_id": ("_team_id", "str"),
            "id": ("id", "str"),
            "role": ("role", "str"),
            "created_at": ("createdAt", "datetime"),
            "created_by": ("createdBy", "str"),
            "modified_at": ("modifiedAt", "datetime"),
            "modified_by": ("modifiedBy", "str"),
        },
    },
    "audit_logs": {
        "endpoint": "/v2/audit/logs",
        "columns": {
            "id": ("id", "str"),
            "event": ("event", "str"),
            "category": ("category", "str"),
            "created_at": ("createdAt", "datetime"),
            "created_by_id": ("createdBy.id", "str"),
            "created_by_name": ("createdBy.name", "str"),
            "created_by_email": ("createdBy.email", "str"),
            "object_id": ("object.id", "str"),
            "object_name": ("object.name", "str"),
            "context_ip": ("context.ip", "str"),
            "context_team_id": ("context.team.id", "str"),
            "context_organization_id": ("context.organization.id", "str"),
            "details": ("details", "json"),
        },
    },
    "board_classifications": {
        "requires": "boards",
        "endpoint": (
            "/v2/orgs/{org_id}/teams/{team_id}/boards/{board_id}/data-classification"
        ),
        "columns": {
            "board_id": ("_board_id", "str"),
            "board_name": ("_board_name", "str"),
            "label_id": ("id", "str"),
            "label_name": ("name", "str"),
            "color": ("color", "str"),
            "description": ("description", "str"),
            "sharing_recommendation": ("sharingRecommendation", "str"),
            "guideline_url": ("guidelineUrl", "str"),
        },
    },
}


def _to_miro_datetime(value: Any) -> str:
    """Coerce an epoch-seconds int/str or ISO 8601 string to Miro's audit-log
    datetime format (``YYYY-MM-DDTHH:MM:SS.000Z``)."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
    else:
        text = str(value).strip()
        if text.isdigit():
            dt = datetime.fromtimestamp(int(text), tz=timezone.utc)
        else:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime(_MIRO_DATETIME)


class MiroCollector(Collector):
    env_prefix = "MIRO"
    display_name = "Miro"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {
        "access_token": True,
        "base_url": False,
    }
    url_config_keys: tuple[str, ...] = ("base_url",)

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        self._base_url = self._config.get("base_url", _DEFAULT_BASE_URL)
        self._org_id: str | None = None

    def _authenticate(self) -> None:
        self._session.headers["Accept"] = "application/json"
        self._session.headers["Authorization"] = (
            f"Bearer {self._config['access_token']}"
        )
        context = self._get(f"{self._base_url}/v1/oauth-token").json()
        self._org_id = (context.get("organization") or {}).get("id")

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "boards":
            return self._fetch_offset_page("/v2/boards", {}, kwargs, cursor)
        if resource == "teams":
            return self._fetch_cursor_page(
                f"/v2/orgs/{self._org_id}/teams", {}, kwargs, cursor
            )
        if resource == "org_members":
            return self._fetch_cursor_page(
                f"/v2/orgs/{self._org_id}/members", {}, kwargs, cursor
            )
        if resource == "audit_logs":
            return self._fetch_audit_page(kwargs, cursor)
        if resource == "board_members":
            return self._fetch_board_fanout(resource, kwargs, cursor)
        if resource == "team_members":
            return self._fetch_team_members_fanout(kwargs, cursor)
        if resource == "board_classifications":
            return self._fetch_board_fanout(resource, kwargs, cursor)
        raise ValueError(f"Unsupported resource '{resource}'")

    # -- pagination shapes ---------------------------------------------------

    def _fetch_offset_page(
        self,
        path: str,
        default_params: dict[str, Any],
        kwargs: dict[str, Any],
        cursor: Any,
    ) -> tuple[list[dict[str, Any]], Any]:
        offset = int(cursor) if cursor is not None else 0
        params = {**default_params, "limit": _PAGE_SIZE, "offset": offset}
        params.update(kwargs)
        payload = self._get(self._base_url + path, params=params).json()
        records = payload.get("data") or []
        total = int(payload.get("total", offset + len(records)))
        next_offset = offset + _PAGE_SIZE
        return records, (next_offset if next_offset < total else None)

    def _fetch_cursor_page(
        self,
        path: str,
        default_params: dict[str, Any],
        kwargs: dict[str, Any],
        cursor: Any,
    ) -> tuple[list[dict[str, Any]], Any]:
        params = {**default_params, "limit": _PAGE_SIZE}
        params.update(kwargs)
        if cursor is not None:
            params["cursor"] = cursor
        payload = self._get(self._base_url + path, params=params).json()
        records = payload.get("data") or []
        next_cursor = payload.get("cursor") or None
        return records, next_cursor

    def _fetch_audit_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        window = self._audit_window(kwargs)
        passthrough = {
            k: v
            for k, v in kwargs.items()
            if k not in ("window_hours", "created_after", "created_before")
        }
        return self._fetch_cursor_page("/v2/audit/logs", window, passthrough, cursor)

    @staticmethod
    def _audit_window(kwargs: dict[str, Any]) -> dict[str, str]:
        window_hours = kwargs.get("window_hours")
        created_after = kwargs.get("created_after")
        created_before = kwargs.get("created_before")
        if window_hours is not None and (
            created_after is not None or created_before is not None
        ):
            raise ValueError(
                "pass either window_hours or created_after/created_before, not both"
            )

        now = datetime.now(timezone.utc)
        if created_after is not None or created_before is not None:
            after = (
                _to_miro_datetime(created_after)
                if created_after is not None
                else _to_miro_datetime(now - timedelta(days=90))
            )
            before = (
                _to_miro_datetime(created_before)
                if created_before is not None
                else _to_miro_datetime(now)
            )
        else:
            hours = (
                int(window_hours)
                if window_hours is not None
                else _DEFAULT_AUDIT_WINDOW_HOURS
            )
            after = _to_miro_datetime(now - timedelta(hours=hours))
            before = _to_miro_datetime(now)
        return {"createdAfter": after, "createdBefore": before}

    # -- fan-outs ----------------------------------------------------------

    def _fetch_board_fanout(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None

        boards = [
            (b.get("id"), b.get("name"), (b.get("team") or {}).get("id"))
            for b in self._get_raw("boards", {})
        ]
        boards = [b for b in boards if b[0]]
        if not boards:
            return [], None

        workers = max(
            1,
            min(
                kwargs.get("max_workers", _DEFAULT_FANOUT_MAX_WORKERS),
                len(boards),
            ),
        )
        fetch_one = (
            self._fetch_members_for_board
            if resource == "board_members"
            else self._fetch_classification_for_board
        )
        records = self._resumable_fanout(resource, boards, fetch_one, workers)
        return records, None

    def _fetch_members_for_board(
        self, board: tuple[str, str | None, str | None]
    ) -> list[dict[str, Any]]:
        board_id, board_name, _ = board
        records: list[dict[str, Any]] = []
        offset = 0
        while True:
            payload = self._get(
                f"{self._base_url}/v2/boards/{board_id}/members",
                params={"limit": _PAGE_SIZE, "offset": offset},
            ).json()
            page = payload.get("data") or []
            for record in page:
                record["_board_id"] = board_id
                record["_board_name"] = board_name
            records.extend(page)
            total = int(payload.get("total", offset + len(page)))
            offset += _PAGE_SIZE
            if offset >= total or not page:
                break
        return records

    def _fetch_classification_for_board(
        self, board: tuple[str, str | None, str | None]
    ) -> dict[str, Any] | None:
        board_id, board_name, team_id = board
        if not team_id:
            return None
        response = self._get(
            f"{self._base_url}/v2/orgs/{self._org_id}/teams/{team_id}"
            f"/boards/{board_id}/data-classification",
            not_found_ok=True,
        )
        if response is None:
            return None  # board has no classification label
        record = response.json()
        record["_board_id"] = board_id
        record["_board_name"] = board_name
        return record

    def _fetch_team_members_fanout(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None

        team_ids = kwargs.get("team_ids")
        if team_ids is None:
            team_ids = [t["id"] for t in self._get_raw("teams", {}) if t.get("id")]
        if not team_ids:
            return [], None

        workers = max(
            1,
            min(kwargs.get("max_workers", _DEFAULT_FANOUT_MAX_WORKERS), len(team_ids)),
        )
        records = self._resumable_fanout(
            "team_members", team_ids, self._fetch_members_for_team, workers
        )
        return records, None

    def _fetch_members_for_team(self, team_id: str) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        cursor: Any = None
        while True:
            params: dict[str, Any] = {"limit": _PAGE_SIZE}
            if cursor is not None:
                params["cursor"] = cursor
            payload = self._get(
                f"{self._base_url}/v2/orgs/{self._org_id}/teams/{team_id}/members",
                params=params,
            ).json()
            page = payload.get("data") or []
            for record in page:
                record["_team_id"] = team_id
            records.extend(page)
            cursor = payload.get("cursor") or None
            if cursor is None or not page:
                break
        return records

    # -- transport --------------------------------------------------------

    def _get(
        self,
        url: str,
        params: dict[str, Any] | None = None,
        *,
        not_found_ok: bool = False,
    ) -> Any:
        response = self._session.get(url, params=params, timeout=30)
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitedSignal(
                retry_after=float(retry_after) if retry_after else None
            )
        if response.status_code == 401:
            raise UnauthorizedSignal()
        if response.status_code == 403:
            try:
                detail = response.json().get("message") or response.text
            except ValueError:
                detail = response.text
            raise PermissionDeniedSignal(
                f"Miro returned 403: {detail} "
                "(this resource needs an Enterprise plan, a Company Admin token, "
                "and the matching scope)"
            )
        if response.status_code == 404 and not_found_ok:
            return None
        response.raise_for_status()
        return response
