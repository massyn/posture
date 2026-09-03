"""Drata collector.

Raw ``requests`` against Drata's Public API
(``https://public-api.drata.com``) — no vendor SDK, static bearer token
auth (``Authorization: Bearer <api_key>``), the same "just set the header"
shape as AppOmni/Snyk/Cloudflare. ``endpoint`` is optional config (Drata
also runs an EU tenant at ``https://public-api.eu.drata.com``); it has a
default rather than being required, normalized the same way ``dnsimple.py``
handles its optional ``endpoint`` override.

Every resource is a real top-level paginated endpoint — no fan-out, no
``derived_from``. Pagination is ``page``/``limit`` (1-indexed) with the
envelope ``{"data": [...], "total": N, "page": P, "limit": L}``; the next
page is requested until ``page * limit >= total``.

Resources: ``controls``, ``monitors``, ``personnel``, ``devices``,
``assets``, ``frameworks``, ``policies``, ``vendors``.

**Caveat:** ``MANIFEST`` column paths below were built from Drata's public
API reference, not a live schema introspection against a real tenant —
same caveat as ``wiz.py``, ``appomni.py``, ``snyk.py``, and
``cloudflare.py``. Verify field names/nesting against a real tenant's
response before relying on this collector.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal
from posture.exceptions import AuthenticationError

logger = logging.getLogger("posture.collectors.drata")

_DEFAULT_ENDPOINT = "https://public-api.drata.com"
_PAGE_SIZE = 100

_CONTROLS_PATH = "/public/controls"
_MONITORS_PATH = "/public/monitors"
_PERSONNEL_PATH = "/public/personnel"
_DEVICES_PATH = "/public/devices"
_ASSETS_PATH = "/public/assets"
_FRAMEWORKS_PATH = "/public/frameworks"
_POLICIES_PATH = "/public/policies"
_VENDORS_PATH = "/public/vendors"

MANIFEST: dict[str, dict[str, Any]] = {
    "controls": {
        "endpoint": _CONTROLS_PATH,
        "columns": {
            "id": ("id", "str"),
            "code": ("code", "str"),
            "name": ("name", "str"),
            "description": ("description", "str"),
            "question": ("question", "str"),
            "activity": ("activity", "str"),
            "is_monitored": ("isMonitored", "bool"),
            "has_evidence": ("hasEvidence", "bool"),
            "is_ready": ("isReady", "bool"),
            "archived_at": ("archivedAt", "datetime"),
            "created_at": ("createdAt", "datetime"),
            "updated_at": ("updatedAt", "datetime"),
        },
    },
    "monitors": {
        "endpoint": _MONITORS_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "description": ("description", "str"),
            "check_status": ("checkStatus", "str"),
            "enabled": ("enabled", "bool"),
            "excluded": ("excluded", "bool"),
            "last_check_at": ("lastCheckAt", "datetime"),
            "next_check_at": ("nextCheckAt", "datetime"),
            "framework_tags": ("frameworkTags", "json"),
            "created_at": ("createdAt", "datetime"),
            "updated_at": ("updatedAt", "datetime"),
        },
    },
    "personnel": {
        "endpoint": _PERSONNEL_PATH,
        "columns": {
            "id": ("id", "str"),
            "first_name": ("firstName", "str"),
            "last_name": ("lastName", "str"),
            "email": ("email", "str"),
            "job_title": ("jobTitle", "str"),
            "employment_status": ("employmentStatus", "str"),
            "employment_type": ("employmentType", "str"),
            "is_active": ("isActive", "bool"),
            "is_contractor": ("isContractor", "bool"),
            "start_date": ("startDate", "datetime"),
            "end_date": ("endDate", "datetime"),
            "separation_date": ("separationDate", "datetime"),
            "created_at": ("createdAt", "datetime"),
            "updated_at": ("updatedAt", "datetime"),
        },
    },
    "devices": {
        "endpoint": _DEVICES_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "serial_number": ("serialNumber", "str"),
            "model": ("model", "str"),
            "os_version": ("osVersion", "str"),
            "mac_address": ("macAddress", "str"),
            "source_type": ("sourceType", "str"),
            "agent_version": ("agentVersion", "str"),
            "compliance_status": ("complianceStatus", "str"),
            "personnel_id": ("personnelId", "str"),
            "personnel_email": ("personnel.email", "str"),
            "is_encrypted": ("isEncrypted", "bool"),
            "is_password_manager_installed": (
                "isPasswordManagerInstalled",
                "bool",
            ),
            "is_antivirus_installed": ("isAntivirusInstalled", "bool"),
            "is_screen_lock_enabled": ("isScreenLockEnabled", "bool"),
            "last_checked_at": ("lastCheckedAt", "datetime"),
            "created_at": ("createdAt", "datetime"),
            "updated_at": ("updatedAt", "datetime"),
        },
    },
    "assets": {
        "endpoint": _ASSETS_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "description": ("description", "str"),
            "type": ("type", "str"),
            "asset_classes": ("assetClasses", "json"),
            "owner_email": ("owner.email", "str"),
            "is_confidential": ("isConfidential", "bool"),
            "removed_at": ("removedAt", "datetime"),
            "created_at": ("createdAt", "datetime"),
            "updated_at": ("updatedAt", "datetime"),
        },
    },
    "frameworks": {
        "endpoint": _FRAMEWORKS_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "slug": ("slug", "str"),
            "description": ("description", "str"),
            "type": ("type", "str"),
            "created_at": ("createdAt", "datetime"),
            "updated_at": ("updatedAt", "datetime"),
        },
    },
    "policies": {
        "endpoint": _POLICIES_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "description": ("description", "str"),
            "version": ("version", "str"),
            "status": ("status", "str"),
            "approved_at": ("approvedAt", "datetime"),
            "last_reviewed_at": ("lastReviewedAt", "datetime"),
            "renewal_date": ("renewalDate", "datetime"),
            "created_at": ("createdAt", "datetime"),
            "updated_at": ("updatedAt", "datetime"),
        },
    },
    "vendors": {
        "endpoint": _VENDORS_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "description": ("description", "str"),
            "website": ("website", "str"),
            "status": ("status", "str"),
            "risk_status": ("riskStatus", "str"),
            "criticality": ("criticality", "str"),
            "tier": ("tier", "str"),
            "contact_name": ("contactName", "str"),
            "contact_email": ("contactEmail", "str"),
            "has_dpa": ("hasDpa", "bool"),
            "has_security_review": ("hasSecurityReview", "bool"),
            "renewal_date": ("renewalDate", "datetime"),
            "created_at": ("createdAt", "datetime"),
            "updated_at": ("updatedAt", "datetime"),
        },
    },
}


class DrataCollector(Collector):
    env_prefix = "DRATA"
    display_name = "Drata"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {"api_key": True, "endpoint": False}
    url_config_keys = ("endpoint",)

    def _resolve_config(self, explicit: dict[str, Any]) -> dict[str, Any]:
        config = super()._resolve_config(explicit)
        config["endpoint"] = self._normalize_url(
            config.get("endpoint") or _DEFAULT_ENDPOINT
        )
        return config

    def _authenticate(self) -> None:
        self._session.headers["Accept"] = "application/json"
        self._session.headers["Authorization"] = f"Bearer {self._config['api_key']}"
        response = self._session.get(
            f"{self._config['endpoint']}{_CONTROLS_PATH}",
            params={"page": 1, "limit": 1},
            timeout=30,
        )
        if response.status_code in (401, 403):
            raise AuthenticationError(
                "Drata rejected the API key",
                source="drata",
                hint="check DRATA_API_KEY (and DRATA_ENDPOINT if on the EU tenant)",
            )

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        manifest = MANIFEST.get(resource)
        if manifest is None:
            raise ValueError(f"Unsupported resource '{resource}'")

        page = int(cursor) if cursor is not None else 1
        params: dict[str, Any] = {"page": page, "limit": _PAGE_SIZE}
        params.update(kwargs)

        payload = self._get_json(
            self._config["endpoint"] + manifest["endpoint"], params
        )
        records = payload.get("data", []) or []
        total = payload.get("total", 0)
        limit = payload.get("limit", _PAGE_SIZE) or _PAGE_SIZE
        next_cursor = page + 1 if page * limit < total else None
        return records, next_cursor

    def _get_json(self, url: str, params: dict[str, Any]) -> dict[str, Any]:
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
                extra={"source": "drata", "status_code": response.status_code},
            )
        response.raise_for_status()
        return response.json()
