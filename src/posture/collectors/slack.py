"""Slack collector, targeting the Enterprise Grid admin API for richer data.

Raw ``requests`` against the Slack Web API (``https://slack.com/api``) — no
vendor SDK. Auth, retry, and reporting come from the base Collector; this
module only knows Slack's endpoints and resource manifests.

Slack's API always answers HTTP 200 and signals failure via a body-level
``{"ok": false, "error": "..."}`` — there is no HTTP 401 to key off. ``_get``
inspects that field: a token-identity error (``invalid_auth``,
``not_authed``, ``token_revoked``, ``token_expired``, ``account_inactive``)
raises ``UnauthorizedSignal`` (retried like any other collector's 401); any
other error (most commonly ``missing_scope`` — an ``admin.*`` call made with
a workspace-level bot token instead of an org-level admin token) raises
immediately with no retry, since retrying an unchanged token against a
permanent scope gap only wastes time. Either way it surfaces as
``IncompleteCollection`` for that resource — a workspace-level token can
still collect ``user_groups``/``channels``/``channel_members`` (regular
Conversations API scopes) while ``users``/``apps`` (admin.* scopes) fail;
each resource is collected independently, so a per-resource failure doesn't
take down the others. See docs/credentials/slack.md for the token tiers.

Resources: ``users``, ``channels``, ``channel_members``, ``user_groups``,
``apps``. Message/file content is deliberately out of scope — that's
DLP/eDiscovery territory, not config/entity posture.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger = logging.getLogger("posture.collectors.slack")

_BASE_URL = "https://slack.com/api"

_USERS_PATH = "/admin.users.list"
_CONVERSATIONS_SEARCH_PATH = "/admin.conversations.search"
_CONVERSATION_MEMBERS_PATH = "/conversations.members"
_USERGROUPS_LIST_PATH = "/usergroups.list"
_APPS_APPROVED_PATH = "/admin.apps.approved.list"

_USERS_PAGE_LIMIT = 200
_CONVERSATIONS_PAGE_LIMIT = 20  # admin.conversations.search caps at 20
_MEMBERS_PAGE_LIMIT = 200
_APPS_PAGE_LIMIT = 100

# Token/identity is broken — retrying (base.py re-runs _authenticate(), which
# is a no-op for a static token, then retries the call) is worth the attempt
# since a rotated token env var picked up by a fresh process could resolve
# it, matching how every other static-token collector (okta, knowbe4) treats
# a 401.
_AUTH_ERROR_CODES = {
    "invalid_auth",
    "not_authed",
    "token_revoked",
    "token_expired",
    "account_inactive",
}

MANIFEST: dict[str, dict[str, Any]] = {
    "users": {
        "endpoint": _USERS_PATH,
        "columns": {
            "id": ("id", "str"),
            "email": ("email", "str"),
            "username": ("username", "str"),
            "full_name": ("full_name", "str"),
            "is_admin": ("is_admin", "bool"),
            "is_owner": ("is_owner", "bool"),
            "is_primary_owner": ("is_primary_owner", "bool"),
            "is_restricted": ("is_restricted", "bool"),
            "is_ultra_restricted": ("is_ultra_restricted", "bool"),
            "is_bot": ("is_bot", "bool"),
            "is_active": ("is_active", "bool"),
            "has_2fa": ("has_2fa", "bool"),
            "has_sso": ("has_sso", "bool"),
            "date_created": ("date_created", "datetime"),
            # 0 when the user was never deactivated/never a time-limited
            # guest — kept as "int" rather than "datetime" so that (the
            # common) zero value doesn't spam a datetime-coercion warning
            # for every non-deactivated/non-guest user.
            "deactivated_ts": ("deactivated_ts", "int"),
            "expiration_ts": ("expiration_ts", "int"),
            "workspaces": ("workspaces", "json"),
        },
    },
    "channels": {
        "endpoint": _CONVERSATIONS_SEARCH_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "purpose": ("purpose", "str"),
            "member_count": ("member_count", "int"),
            "created": ("created", "datetime"),
            "creator_id": ("creator_id", "str"),
            "is_private": ("is_private", "bool"),
            "is_archived": ("is_archived", "bool"),
            "is_general": ("is_general", "bool"),
            # 0 for a channel with no activity yet — see deactivated_ts above.
            "last_activity_ts": ("last_activity_ts", "int"),
            "is_ext_shared": ("is_ext_shared", "bool"),
            "is_global_shared": ("is_global_shared", "bool"),
            "is_org_shared": ("is_org_shared", "bool"),
            "is_org_default": ("is_org_default", "bool"),
            "is_org_mandatory": ("is_org_mandatory", "bool"),
            "is_frozen": ("is_frozen", "bool"),
            "is_pending_ext_shared": ("is_pending_ext_shared", "bool"),
            "connected_team_ids": ("connected_team_ids", "json"),
        },
    },
    "channel_members": {
        # Not derived_from "channels": conversations.members is a separate
        # per-channel network call returning a flat list of user id strings,
        # not data nested inside a raw channel record. channel_id is
        # injected into each constructed record at fetch time (see
        # _fetch_channel_members_page/_drain_members).
        "endpoint": _CONVERSATION_MEMBERS_PATH,
        "columns": {
            "channel_id": ("channel_id", "str"),
            "user_id": ("user_id", "str"),
        },
    },
    "user_groups": {
        "endpoint": _USERGROUPS_LIST_PATH,
        "columns": {
            "id": ("id", "str"),
            "team_id": ("team_id", "str"),
            "name": ("name", "str"),
            "description": ("description", "str"),
            "handle": ("handle", "str"),
            "is_external": ("is_external", "bool"),
            "date_create": ("date_create", "datetime"),
            "date_update": ("date_update", "datetime"),
            # 0 while the group is still active.
            "date_delete": ("date_delete", "int"),
            "auto_type": ("auto_type", "str"),
            "created_by": ("created_by", "str"),
            "updated_by": ("updated_by", "str"),
            "deleted_by": ("deleted_by", "str"),
            "user_count": ("user_count", "int"),
        },
    },
    "apps": {
        "endpoint": _APPS_APPROVED_PATH,
        "columns": {
            "id": ("app.id", "str"),
            "name": ("app.name", "str"),
            "description": ("app.description", "str"),
            "is_app_directory_approved": ("app.is_app_directory_approved", "bool"),
            "is_internal": ("app.is_internal", "bool"),
            "developer_type": ("app.developer_type", "str"),
            "socket_mode_enabled": ("app.socket_mode_enabled", "bool"),
            "scopes": ("scopes", "json"),
            "date_updated": ("date_updated", "datetime"),
            "last_resolved_by_actor_id": ("last_resolved_by.actor_id", "str"),
            "last_resolved_by_actor_type": ("last_resolved_by.actor_type", "str"),
        },
    },
}


class SlackError(Exception):
    def __init__(self, error_code: str) -> None:
        super().__init__(f"Slack API error: {error_code}")
        self.error_code = error_code


class SlackCollector(Collector):
    env_prefix = "SLACK"
    display_name = "Slack"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {"token": True}

    def _authenticate(self) -> None:
        self._session.headers["Authorization"] = f"Bearer {self._config['token']}"
        self._session.headers["Accept"] = "application/json"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "users":
            return self._fetch_users_page(kwargs, cursor)
        if resource == "channels":
            return self._fetch_channels_page(kwargs, cursor)
        if resource == "channel_members":
            return self._fetch_channel_members_page(kwargs, cursor)
        if resource == "user_groups":
            return self._fetch_user_groups_page(kwargs, cursor)
        if resource == "apps":
            return self._fetch_apps_page(kwargs, cursor)
        raise ValueError(f"Unsupported resource '{resource}'")

    def _fetch_users_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        params: dict[str, Any] = {"limit": _USERS_PAGE_LIMIT}
        if cursor:
            params["cursor"] = cursor
        params.update(kwargs)
        body = self._get(_USERS_PATH, params, resource="users")
        return body["users"], body["response_metadata"]["next_cursor"] or None

    def _fetch_channels_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        params: dict[str, Any] = {"limit": _CONVERSATIONS_PAGE_LIMIT}
        if cursor:
            params["cursor"] = cursor
        params.update(kwargs)
        body = self._get(_CONVERSATIONS_SEARCH_PATH, params, resource="channels")
        return body["conversations"], body["response_metadata"]["next_cursor"] or None

    def _fetch_channel_members_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # entire fan-out already completed on first call

        channel_ids = kwargs.get("channel_ids")
        if channel_ids is None:
            raw_channels = self._get_raw("channels", {})
            channel_ids = [c["id"] for c in raw_channels if c.get("id")]
        if not channel_ids:
            return [], None

        records = self._resumable_fanout(
            "channel_members", channel_ids, self._drain_members, max_workers=5
        )
        return records, None

    def _drain_members(self, channel_id: str) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        cursor: str | None = None
        while True:
            params: dict[str, Any] = {
                "channel": channel_id,
                "limit": _MEMBERS_PAGE_LIMIT,
            }
            if cursor:
                params["cursor"] = cursor
            body = self._get(
                _CONVERSATION_MEMBERS_PATH, params, resource="channel_members"
            )
            for user_id in body["members"]:
                records.append({"channel_id": channel_id, "user_id": user_id})
            cursor = body["response_metadata"]["next_cursor"] or None
            if not cursor:
                break
        return records

    def _fetch_user_groups_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # usergroups.list is not paginated

        params: dict[str, Any] = {"include_count": "true"}
        params.update(kwargs)
        body = self._get(_USERGROUPS_LIST_PATH, params, resource="user_groups")
        return body["usergroups"], None

    def _fetch_apps_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        params: dict[str, Any] = {"limit": _APPS_PAGE_LIMIT}
        if cursor:
            params["cursor"] = cursor
        params.update(kwargs)
        body = self._get(_APPS_APPROVED_PATH, params, resource="apps")
        return body["approved_apps"], body["response_metadata"]["next_cursor"] or None

    def _get(
        self, path: str, params: dict[str, Any], *, resource: str
    ) -> dict[str, Any]:
        response = self._session.get(_BASE_URL + path, params=params, timeout=30)
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitedSignal(
                retry_after=float(retry_after) if retry_after else None
            )
        response.raise_for_status()
        body = response.json()
        if not body.get("ok"):
            error_code = body.get("error", "unknown_error")
            if error_code in _AUTH_ERROR_CODES:
                raise UnauthorizedSignal()
            logger.warning(
                "Slack API error",
                extra={"source": "slack", "resource": resource, "error": error_code},
            )
            raise SlackError(error_code)
        return body
