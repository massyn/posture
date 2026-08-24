"""SentinelOne collector.

Singularity Platform EDR/XDR. Raw ``requests`` against the tenant-scoped
Management API (``https://<console>.sentinelone.net/web/api/v2.1``) — no
vendor SDK.

Auth is a static API token generated per-user in the console (Settings >
Users > API Token), sent as ``Authorization: ApiToken <token>`` — same
"just set the header" shape as AppOmni/Snyk/UpGuard. Unlike those, the
token itself carries the generating user's role/scope rather than being
independently scoped by an admin at creation time — a token minted by a
site-scoped viewer account can't reach account-level endpoints, so the
read-only shape here is "provision a dedicated, minimally-privileged
viewer user, then generate that user's token," not "create an API client
with read scopes." ``console_url`` is required config (no cross-tenant
discovery mechanism, same shape as Wiz's ``api_endpoint``).

Pagination is a single cursor shape shared by every list endpoint here —
``{"pagination": {"totalItems", "nextCursor"}, "data": [...]}`` — simpler
than most collectors in this codebase: one ``_fetch_page`` implementation
serves every resource, keyed only by endpoint path.

Resources: ``agents``, ``threats``, ``alerts``, ``sites``, ``groups``,
``installed_applications``.

``threats`` and ``alerts`` deliberately overlap: ``threats`` is
SentinelOne's older endpoint-threat model, ``alerts``
(``cloud-detection/alerts``, v2.1-only) is the newer unified XDR alert
model that supersedes it on more recent consoles. Both are included
per explicit instruction rather than picking one — which one a given
tenant actually populates depends on their console version/configuration,
and this can be revisited (retiring whichever turns out redundant) once
verified against a real tenant.

``installed_applications`` hits a top-level, already-paginated endpoint
(``/installed-applications``, filterable by ``agentUuid`` etc.) rather
than requiring a per-agent fan-out — unlike Jamf's/Intune's per-device
detail calls, SentinelOne exposes the whole fleet's software inventory as
one resource.

Deliberately out of scope for this initial cut: ``application-risks``
(SentinelOne's per-app CVE/vulnerability feed) — it lives under Singularity
Ranger Insights, a separately licensed module (the same reasoning that
splits CrowdStrike Falcon Cloud Security into ``crowdstrike_cspm.py``
rather than folding it into ``crowdstrike.py``), and its response schema
could not be corroborated closely enough to commit to a manifest here.
Response-action surfaces (agent disconnect/shutdown/uninstall, remote
script execution, STAR custom detection rules, blocklist/exclusion
management, Deep Visibility queries) are out of scope entirely — this is a
read-only collection library.

**Caveat — not live-verified:** ``MANIFEST`` column paths were built from
SentinelOne's public API reference and several third-party connectors
built against this API (Cortex XSOAR, Brinqa, Vulcan Cyber), not a live
schema introspection against a real tenant — same caveat tier as
``wiz.py``, ``appomni.py``, ``kandji.py``, and others in this file's peers.
``agents`` and ``threats`` are well-corroborated across multiple
independent sources; ``alerts``, ``sites``, and ``groups`` are lower
confidence — their exact field names could not be independently confirmed
and are a best-effort guess at SentinelOne's naming conventions elsewhere
in the product. Verify field names/nesting against a real tenant's
response before relying on this collector, particularly for ``alerts``.
"""

from __future__ import annotations

import logging
from typing import Any

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger = logging.getLogger("posture.collectors.sentinelone")

_PAGE_LIMIT = 1000

_ENDPOINTS = {
    "agents": "/web/api/v2.1/agents",
    "threats": "/web/api/v2.1/threats",
    "alerts": "/web/api/v2.1/cloud-detection/alerts",
    "sites": "/web/api/v2.1/sites",
    "groups": "/web/api/v2.1/groups",
    "installed_applications": "/web/api/v2.1/installed-applications",
}

MANIFEST: dict[str, dict[str, Any]] = {
    "agents": {
        "endpoint": _ENDPOINTS["agents"],
        "columns": {
            "agent_id": ("id", "str"),
            "uuid": ("uuid", "str"),
            "computer_name": ("computerName", "str"),
            "os_type": ("osType", "str"),
            "os_revision": ("osRevision", "str"),
            "agent_version": ("agentVersion", "str"),
            "serial_number": ("serialNumber", "str"),
            "external_ip": ("externalIp", "str"),
            "network_status": ("networkStatus", "str"),
            "is_active": ("isActive", "bool"),
            "is_decommissioned": ("isDecommissioned", "bool"),
            "infected": ("infected", "bool"),
            "site_id": ("siteId", "str"),
            "site_name": ("siteName", "str"),
            "group_id": ("groupId", "str"),
            "group_name": ("groupName", "str"),
            "account_id": ("accountId", "str"),
            "account_name": ("accountName", "str"),
            "registered_at": ("registeredAt", "datetime"),
            "last_active_date": ("lastActiveDate", "datetime"),
            "updated_at": ("updatedAt", "datetime"),
        },
    },
    "threats": {
        "endpoint": _ENDPOINTS["threats"],
        "columns": {
            "threat_id": ("id", "str"),
            "classification": ("threatInfo.classification", "str"),
            "threat_name": ("threatInfo.threatName", "str"),
            "incident_status": ("threatInfo.incidentStatusDescription", "str"),
            "mitigation_status": ("threatInfo.mitigationStatusDescription", "str"),
            "confidence_level": ("threatInfo.confidenceLevel", "str"),
            "file_path": ("threatInfo.filePath", "str"),
            "file_size": ("threatInfo.fileSize", "int"),
            "created_at": ("threatInfo.createdAt", "datetime"),
            "updated_at": ("threatInfo.updatedAt", "datetime"),
            "agent_uuid": ("agentRealtimeInfo.agentUuid", "str"),
        },
    },
    "alerts": {
        # Lower-confidence manifest — see module docstring caveat. Only
        # fields corroborated across multiple sources are included; the
        # full alertInfo/ruleInfo nesting SentinelOne actually returns was
        # not confirmed.
        "endpoint": _ENDPOINTS["alerts"],
        "columns": {
            "alert_id": ("id", "str"),
            "agent_uuid": ("agentRealtimeInfo.agentUuid", "str"),
            "created_at": ("alertInfo.createdAt", "datetime"),
            "updated_at": ("alertInfo.updatedAt", "datetime"),
        },
    },
    "sites": {
        "endpoint": _ENDPOINTS["sites"],
        "columns": {
            "site_id": ("id", "str"),
            "name": ("name", "str"),
            "state": ("state", "str"),
            "account_id": ("accountId", "str"),
            "account_name": ("accountName", "str"),
            "created_at": ("createdAt", "datetime"),
        },
    },
    "groups": {
        "endpoint": _ENDPOINTS["groups"],
        "columns": {
            "group_id": ("id", "str"),
            "name": ("name", "str"),
            "type": ("type", "str"),
            "site_id": ("siteId", "str"),
            "is_default": ("isDefault", "bool"),
        },
    },
    "installed_applications": {
        "endpoint": _ENDPOINTS["installed_applications"],
        "columns": {
            "agent_uuid": ("agentUuid", "str"),
            "agent_computer_name": ("agentComputerName", "str"),
            "name": ("name", "str"),
            "version": ("version", "str"),
            "publisher": ("publisher", "str"),
            "size": ("size", "int"),
            "installed_date": ("installedDate", "datetime"),
        },
    },
}


class SentinelOneCollector(Collector):
    env_prefix = "SENTINELONE"
    display_name = "SentinelOne"
    manifest = MANIFEST
    config_keys = {"console_url": True, "api_token": True}
    url_config_keys = ("console_url",)

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        self._base_url = self._config["console_url"]

    def _authenticate(self) -> None:
        self._session.headers["Accept"] = "application/json"
        self._session.headers["Authorization"] = f"ApiToken {self._config['api_token']}"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        endpoint = self.manifest[resource]["endpoint"]
        params: dict[str, Any] = {"limit": _PAGE_LIMIT}
        if cursor is not None:
            params["cursor"] = cursor
        params.update(kwargs)

        response = self._get(self._base_url + endpoint, params=params)
        payload = response.json()
        records = payload.get("data", []) or []
        next_cursor = (payload.get("pagination") or {}).get("nextCursor")
        return records, next_cursor

    def _get(self, url: str, params: dict[str, Any] | None = None) -> Any:
        response = self._session.get(url, params=params, timeout=30)
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitedSignal(
                retry_after=float(retry_after) if retry_after else None
            )
        if response.status_code in (401, 403):
            raise UnauthorizedSignal()
        if response.status_code != 200:
            logger.warning(
                "unexpected status code",
                extra={"source": "sentinelone", "status_code": response.status_code},
            )
        response.raise_for_status()
        return response
