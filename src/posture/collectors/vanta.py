"""Vanta collector.

Raw ``requests`` against Vanta's REST API v1 — no vendor SDK. Auth is
OAuth2 client-credentials against a fixed token host
(``https://api.vanta.com/oauth/token``), the same shape as ``wiz.py`` but
with no regional/tenant discovery: Vanta has one global API host, so unlike
Wiz there is no ``token_url``/``api_endpoint`` override needed.

Every resource is a real top-level paginated endpoint (no fan-out, no
``derived_from`` — Vanta has no "list of objects nested in a parent"
resources in this initial cut). Pagination is cursor-based:
``pageSize``/``pageCursor`` query params, with the envelope
``results.data`` / ``results.pageInfo.hasNextPage`` /
``results.pageInfo.endCursor`` — a REST cursor shape, not GraphQL's, but
the same cursor-threading idea as ``wiz.py``.

Resources: ``controls``, ``documents``, ``frameworks``, ``groups``,
``integrations``, ``monitored_computers``, ``people``, ``tests``,
``vulnerabilities``, ``vulnerable_assets``, ``vulnerability_remediations``.

**Caveat:** ``MANIFEST`` column paths below were built from Vanta's public
API reference and a prior in-house extraction script, not a live schema
introspection against a real tenant — same caveat as ``wiz.py``,
``appomni.py``, ``snyk.py``, ``cloudflare.py``, ``dnsimple.py``, and
``phriendly_phishing.py``. Verify field names/nesting against a real
tenant's response before relying on this collector, and correct
``MANIFEST`` if they don't match.
"""

from __future__ import annotations

import logging
from typing import Any

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal
from posture.exceptions import AuthenticationError

logger = logging.getLogger("posture.collectors.vanta")

_TOKEN_URL = "https://api.vanta.com/oauth/token"
_TOKEN_SCOPE = "vanta-api.all:read vanta-api.all:write"
_BASE_URL = "https://api.vanta.com"
_PAGE_SIZE = 100

_CONTROLS_PATH = "/v1/controls"
_DOCUMENTS_PATH = "/v1/documents"
_FRAMEWORKS_PATH = "/v1/frameworks"
_GROUPS_PATH = "/v1/groups"
_INTEGRATIONS_PATH = "/v1/integrations"
_MONITORED_COMPUTERS_PATH = "/v1/monitored-computers"
_PEOPLE_PATH = "/v1/people"
_TESTS_PATH = "/v1/tests"
_VULNERABILITIES_PATH = "/v1/vulnerabilities"
_VULNERABLE_ASSETS_PATH = "/v1/vulnerable-assets"
_VULNERABILITY_REMEDIATIONS_PATH = "/v1/vulnerability-remediations"

MANIFEST: dict[str, dict[str, Any]] = {
    "controls": {
        "endpoint": _CONTROLS_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "description": ("description", "str"),
            "question": ("question", "str"),
            "created_at": ("createdAt", "datetime"),
            "updated_at": ("updatedAt", "datetime"),
            "deleted_at": ("deletedAt", "datetime"),
        },
    },
    "documents": {
        "endpoint": _DOCUMENTS_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "description": ("description", "str"),
            "document_type": ("documentType", "str"),
            "is_archived": ("isArchived", "bool"),
            "owner_id": ("ownerId", "str"),
            "created_at": ("createdAt", "datetime"),
            "updated_at": ("updatedAt", "datetime"),
        },
    },
    "frameworks": {
        "endpoint": _FRAMEWORKS_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "description": ("description", "str"),
            "created_at": ("createdAt", "datetime"),
            "updated_at": ("updatedAt", "datetime"),
        },
    },
    "groups": {
        "endpoint": _GROUPS_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "source": ("source", "str"),
            "created_at": ("createdAt", "datetime"),
            "updated_at": ("updatedAt", "datetime"),
        },
    },
    "integrations": {
        "endpoint": _INTEGRATIONS_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "display_name": ("displayName", "str"),
            "connection_id": ("connectionId", "str"),
            "created_at": ("createdAt", "datetime"),
            "updated_at": ("updatedAt", "datetime"),
        },
    },
    "monitored_computers": {
        "endpoint": _MONITORED_COMPUTERS_PATH,
        "columns": {
            "id": ("id", "str"),
            "owner_id": ("ownerId", "str"),
            "owner_email": ("ownerEmail", "str"),
            "owner_name": ("ownerName", "str"),
            "device_type": ("deviceType", "str"),
            "os_version": ("osVersion", "str"),
            "agent_version": ("agentVersion", "str"),
            "is_encrypted": ("isEncrypted", "bool"),
            "firewall_enabled": ("firewallEnabled", "bool"),
            "screen_lock_enabled": ("screenLockEnabled", "bool"),
            "auto_update_enabled": ("autoUpdateEnabled", "bool"),
            "last_pinged_at": ("lastPingedAt", "datetime"),
        },
    },
    "people": {
        "endpoint": _PEOPLE_PATH,
        "columns": {
            "id": ("id", "str"),
            "email": ("email", "str"),
            "full_name": ("fullName", "str"),
            "given_name": ("givenName", "str"),
            "family_name": ("familyName", "str"),
            "is_vanta_owner": ("isVantaOwner", "bool"),
            "employment_status": ("employmentStatus", "str"),
            "hire_date": ("hireDate", "datetime"),
            "end_date": ("endDate", "datetime"),
        },
    },
    "tests": {
        "endpoint": _TESTS_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "description": ("description", "str"),
            "status": ("status", "str"),
            "entity_type": ("entityType", "str"),
            "created_at": ("createdAt", "datetime"),
            "updated_at": ("updatedAt", "datetime"),
        },
    },
    "vulnerabilities": {
        "endpoint": _VULNERABILITIES_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "description": ("description", "str"),
            "severity": ("severity", "str"),
            "cve": ("cve", "str"),
            "asset_id": ("assetId", "str"),
            "status": ("status", "str"),
            "detected_at": ("detectedAt", "datetime"),
            "remediate_by": ("remediateBy", "datetime"),
        },
    },
    "vulnerable_assets": {
        "endpoint": _VULNERABLE_ASSETS_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "type": ("type", "str"),
            "provider": ("provider", "str"),
            "vulnerability_count": ("vulnerabilityCount", "int"),
        },
    },
    "vulnerability_remediations": {
        "endpoint": _VULNERABILITY_REMEDIATIONS_PATH,
        "columns": {
            "id": ("id", "str"),
            "vulnerability_id": ("vulnerabilityId", "str"),
            "asset_id": ("assetId", "str"),
            "status": ("status", "str"),
            "remediated_at": ("remediatedAt", "datetime"),
        },
    },
}


class VantaCollector(Collector):
    env_prefix = "VANTA"
    display_name = "Vanta"
    manifest = MANIFEST
    required_config_keys = ("client_id", "client_secret")

    def _authenticate(self) -> None:
        response = self._session.post(
            _TOKEN_URL,
            json={
                "client_id": self._config["client_id"],
                "client_secret": self._config["client_secret"],
                "scope": _TOKEN_SCOPE,
                "grant_type": "client_credentials",
            },
            timeout=30,
        )
        if response.status_code == 401:
            raise AuthenticationError(
                "Vanta rejected client credentials",
                source="vanta",
                hint="check VANTA_CLIENT_ID / VANTA_CLIENT_SECRET",
            )
        response.raise_for_status()

        token = response.json()["access_token"]
        self._session.headers["Authorization"] = f"Bearer {token}"
        self._session.headers["Content-Type"] = "application/json"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        manifest = MANIFEST.get(resource)
        if manifest is None:
            raise ValueError(f"Unsupported resource '{resource}'")

        params: dict[str, Any] = {"pageSize": _PAGE_SIZE}
        params.update(kwargs)
        if cursor is not None:
            params["pageCursor"] = cursor

        response = self._get(_BASE_URL + manifest["endpoint"], params=params)
        payload = response.json()

        results = payload.get("results", {})
        records = results.get("data", []) or []
        page_info = results.get("pageInfo", {})
        next_cursor = (
            page_info.get("endCursor") if page_info.get("hasNextPage") else None
        )
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
                extra={"source": "vanta", "status_code": response.status_code},
            )
        response.raise_for_status()
        return response
