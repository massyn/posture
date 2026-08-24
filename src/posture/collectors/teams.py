"""Microsoft Teams collector.

Raw ``requests`` against Microsoft Graph — no vendor SDK. Auth (shared with
``intune.py``/``mde.py`` via ``_azure_oauth.py``) and OData
``value``/``@odata.nextLink`` pagination follow the same pattern as
``intune.py``; read that module's docstring first if this one is unfamiliar.

Graph has no "list all teams" endpoint — a team *is* a Microsoft 365 group
with Teams provisioned on it, so ``teams`` lists groups filtered to
``resourceProvisioningOptions/Any(x:x eq 'Team')`` (Microsoft's own
documented approach, see
https://learn.microsoft.com/en-us/graph/teams-list-all-teams).

``team_settings``, ``channels``, ``installed_apps``, and ``team_members``
are all per-team fan-outs off ``teams``' id list, the same
``requires``/``_resumable_fanout`` shape as Intune's
``managed_device_detail``/``attack_simulation_users``:
``team_settings`` fetches one record per team id (``GET /teams/{id}``, not
paginated); the other three each paginate their own per-team endpoint and
inject ``_team_id`` client-side, since none of their response bodies carry
it back.

``team_settings`` (``memberSettings.allowAddRemoveApps``,
``guestSettings.allowCreateUpdateChannels``, per-team owner/member/guest
counts) is this collector's highest-value resource for posture — it's
actual tenant governance config, not just a roster. ``channels``'
``membership_type`` flags private/shared channels, which (like Slack
Connect channels) bypass a team's normal owner-visible governance.

**Out of scope, deliberately:** tenant-wide Teams admin policies (messaging
policy, meeting policy, app-permission policy, external/federation access)
are not exposed via Microsoft Graph at all — they only exist in the
separate Teams PowerShell module (``MicrosoftTeams``), which isn't a
client-credentials-compatible Graph API. There is no way to collect them
through this collector.

Resources: ``teams``, ``team_settings`` (requires teams ids),
``channels`` (requires teams ids), ``installed_apps`` (requires teams
ids), ``team_members`` (requires teams ids).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar

import requests

from posture.base import Collector
from posture.collectors._azure_oauth import (
    fetch_azure_ad_token,
    graph_get_json,
    odata_get_page,
)

logger = logging.getLogger("posture.collectors.teams")

_GRAPH_BASE_URL = "https://graph.microsoft.com"
_PAGE_SIZE = 100

# Per-team fan-out (team_settings, channels, installed_apps, team_members)
# issues one or more requests per team. Same rationale/bound as Intune's
# _MAX_FANOUT_WORKERS.
_MAX_FANOUT_WORKERS = 10

_TEAMS_FILTER = "resourceProvisioningOptions/Any(x:x eq 'Team')"

_ENDPOINTS = {
    "teams": "/v1.0/groups",
    "team_settings": "/v1.0/teams/{id}",
    "channels": "/v1.0/teams/{id}/channels",
    "installed_apps": "/v1.0/teams/{id}/installedApps",
    "team_members": "/v1.0/teams/{id}/members",
}

_PER_TEAM_RESOURCES = ("channels", "installed_apps", "team_members")

MANIFEST: dict[str, dict[str, Any]] = {
    "teams": {
        "endpoint": _ENDPOINTS["teams"],
        "columns": {
            "team_id": ("id", "str"),
            "display_name": ("displayName", "str"),
            "description": ("description", "str"),
            "mail_nickname": ("mailNickname", "str"),
            "visibility": ("visibility", "str"),
            "mail_enabled": ("mailEnabled", "bool"),
            "created_date_time": ("createdDateTime", "datetime"),
        },
    },
    "team_settings": {
        # Not derived_from "teams": each team's settings are their own
        # network call by id, not data nested inside the group list record.
        # requires="teams" so the id list is served from the on-disk cache
        # instead of re-collecting the full resource from the network a
        # second time.
        "endpoint": _ENDPOINTS["team_settings"],
        "requires": "teams",
        "columns": {
            "team_id": ("_team_id", "str"),
            "is_archived": ("isArchived", "bool"),
            "member_allow_create_update_channels": (
                "memberSettings.allowCreateUpdateChannels",
                "bool",
            ),
            "member_allow_delete_channels": (
                "memberSettings.allowDeleteChannels",
                "bool",
            ),
            "member_allow_add_remove_apps": (
                "memberSettings.allowAddRemoveApps",
                "bool",
            ),
            "member_allow_create_update_remove_tabs": (
                "memberSettings.allowCreateUpdateRemoveTabs",
                "bool",
            ),
            "member_allow_create_update_remove_connectors": (
                "memberSettings.allowCreateUpdateRemoveConnectors",
                "bool",
            ),
            "guest_allow_create_update_channels": (
                "guestSettings.allowCreateUpdateChannels",
                "bool",
            ),
            "guest_allow_delete_channels": (
                "guestSettings.allowDeleteChannels",
                "bool",
            ),
            "messaging_allow_user_edit_messages": (
                "messagingSettings.allowUserEditMessages",
                "bool",
            ),
            "messaging_allow_user_delete_messages": (
                "messagingSettings.allowUserDeleteMessages",
                "bool",
            ),
            "messaging_allow_owner_delete_messages": (
                "messagingSettings.allowOwnerDeleteMessages",
                "bool",
            ),
            "messaging_allow_team_mentions": (
                "messagingSettings.allowTeamMentions",
                "bool",
            ),
            "messaging_allow_channel_mentions": (
                "messagingSettings.allowChannelMentions",
                "bool",
            ),
            "discovery_show_in_search": (
                "discoverySettings.showInTeamsSearchAndSuggestions",
                "bool",
            ),
            "owners_count": ("summary.ownersCount", "int"),
            "members_count": ("summary.membersCount", "int"),
            "guests_count": ("summary.guestsCount", "int"),
        },
    },
    "channels": {
        # Not derived_from "teams": each team's channels are their own
        # paginated network call. _team_id is injected client-side (see
        # _fetch_per_team_page).
        "endpoint": _ENDPOINTS["channels"],
        "requires": "teams",
        "columns": {
            "team_id": ("_team_id", "str"),
            "channel_id": ("id", "str"),
            "display_name": ("displayName", "str"),
            "description": ("description", "str"),
            "membership_type": ("membershipType", "str"),
            "is_archived": ("isArchived", "bool"),
            "created_date_time": ("createdDateTime", "datetime"),
            "web_url": ("webUrl", "str"),
        },
    },
    "installed_apps": {
        # Not derived_from "teams": each team's installed apps are their own
        # paginated network call, expanded with teamsAppDefinition for the
        # app's own name/version/publisher metadata. _team_id is injected
        # client-side (see _fetch_per_team_page).
        "endpoint": _ENDPOINTS["installed_apps"],
        "requires": "teams",
        "columns": {
            "team_id": ("_team_id", "str"),
            "installation_id": ("id", "str"),
            "teams_app_id": ("teamsAppDefinition.teamsAppId", "str"),
            "azure_ad_app_id": ("teamsAppDefinition.azureADAppId", "str"),
            "display_name": ("teamsAppDefinition.displayName", "str"),
            "version": ("teamsAppDefinition.version", "str"),
            "publishing_state": ("teamsAppDefinition.publishingState", "str"),
        },
    },
    "team_members": {
        # Not derived_from "teams": each team's members are their own
        # paginated network call. _team_id is injected client-side (see
        # _fetch_per_team_page).
        "endpoint": _ENDPOINTS["team_members"],
        "requires": "teams",
        "columns": {
            "team_id": ("_team_id", "str"),
            "membership_id": ("id", "str"),
            "roles": ("roles", "json"),
            "display_name": ("displayName", "str"),
            "user_id": ("userId", "str"),
            "email": ("email", "str"),
        },
    },
}


class TeamsCollector(Collector):
    env_prefix = "TEAMS"
    display_name = "Microsoft Teams"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {
        "tenant_id": True,
        "client_id": True,
        "client_secret": True,
    }

    def _authenticate(self) -> None:
        token = fetch_azure_ad_token(
            self._session,
            tenant_id=self._config["tenant_id"],
            client_id=self._config["client_id"],
            client_secret=self._config["client_secret"],
            scope="https://graph.microsoft.com/.default",
            source="Teams",
        )
        self._session.headers["Authorization"] = f"Bearer {token.access_token}"
        self._token_expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=token.expires_in
        )

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "teams":
            return self._fetch_teams_page(kwargs, cursor)
        if resource == "team_settings":
            return self._fetch_team_settings_page(kwargs, cursor)
        if resource in _PER_TEAM_RESOURCES:
            return self._fetch_per_team_fanout_page(resource, kwargs, cursor)
        raise ValueError(f"Unsupported resource '{resource}'")

    def _fetch_teams_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return odata_get_page(self._session, cursor, None)

        url = _GRAPH_BASE_URL + _ENDPOINTS["teams"]
        params: dict[str, Any] = {"$top": _PAGE_SIZE, "$filter": _TEAMS_FILTER}
        params.update(kwargs)
        return odata_get_page(self._session, url, params)

    def _team_ids(self, kwargs: dict[str, Any]) -> list[str]:
        team_ids = kwargs.get("team_ids")
        if team_ids is None:
            raw_teams = self._get_raw("teams", {})
            team_ids = [str(t["id"]) for t in raw_teams if t.get("id") is not None]
        return team_ids

    def _fetch_team_settings_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # all ids already fetched on the first call

        team_ids = self._team_ids(kwargs)
        if not team_ids:
            return [], None

        def _fetch_one(team_id: str) -> dict[str, Any] | None:
            url = _GRAPH_BASE_URL + _ENDPOINTS["team_settings"].format(id=team_id)
            try:
                record = graph_get_json(self._session, url, None)
            except requests.exceptions.HTTPError as exc:
                status = exc.response.status_code if exc.response is not None else None
                if status == 404:
                    # Team deleted/deprovisioned since the teams list was
                    # pulled — per-team, not a collection-wide failure.
                    logger.info(
                        "team_settings: no settings for team (404), skipping",
                        extra={"source": self.env_prefix.lower(), "team_id": team_id},
                    )
                    return None
                raise
            record["_team_id"] = team_id
            return record

        records = self._resumable_fanout(
            "team_settings", team_ids, _fetch_one, _MAX_FANOUT_WORKERS
        )
        return records, None

    def _fetch_per_team_fanout_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # entire fan-out already completed on first call

        team_ids = self._team_ids(kwargs)
        if not team_ids:
            return [], None

        def _fetch_one(team_id: str) -> list[dict[str, Any]]:
            try:
                return self._drain_per_team(resource, team_id)
            except requests.exceptions.HTTPError as exc:
                status = exc.response.status_code if exc.response is not None else None
                if status == 404:
                    # Team deleted/deprovisioned since the teams list was
                    # pulled — per-team, not a collection-wide failure.
                    logger.info(
                        "%s: no data for team (404), skipping",
                        resource,
                        extra={"source": self.env_prefix.lower(), "team_id": team_id},
                    )
                    return []
                raise

        records = self._resumable_fanout(
            resource, team_ids, _fetch_one, _MAX_FANOUT_WORKERS
        )
        return records, None

    def _drain_per_team(self, resource: str, team_id: str) -> list[dict[str, Any]]:
        url = _GRAPH_BASE_URL + _ENDPOINTS[resource].format(id=team_id)
        # channels/installedApps/members don't support $top — Graph rejects
        # it outright ("Query option 'Top' is not allowed"). Only
        # team_members actually paginates via @odata.nextLink; the others
        # return their full (small) list in one response regardless.
        params: dict[str, Any] | None = None
        if resource == "team_members":
            params = {"$top": _PAGE_SIZE}
        elif resource == "installed_apps":
            params = {"$expand": "teamsAppDefinition"}

        records: list[dict[str, Any]] = []
        while url:
            page_records, next_link = odata_get_page(self._session, url, params)
            for record in page_records:
                record["_team_id"] = team_id
            records.extend(page_records)
            url = next_link
            params = None  # next_link is opaque and already carries params
        return records
