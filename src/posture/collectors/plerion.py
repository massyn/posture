"""Plerion (CNAPP) collector.

Raw ``requests`` against Plerion's REST API v1 (``https://<region>.api.
plerion.com``), no vendor SDK — generic REST, static bearer API key
(``Authorization: Bearer <token>``), same "just set the header" shape as
AppOmni/Snyk/UpGuard. ``endpoint`` is required config (the tenant's regional
host, e.g. ``au.api.plerion.com``) — no cross-tenant discovery, same
no-discovery shape as Wiz's ``api_endpoint``/Kandji's ``api_url``.

Three resources to start (Plerion's full surface is much broader — findings/
alerts/assets/asset groups/vulnerabilities/exemptions/compliance & well-
architected reports/AWS access grants/custom checks/code security/risks/
audit logs — the rest are deliberately out of scope for this initial cut):

- ``findings`` (``GET /v1/tenant/findings``) — cursor-paginated
  (``meta.cursor``/``meta.hasNextPage``; the endpoint's documented query
  params include ``cursor`` but not ``page``, unlike the other two).
- ``assets`` (``GET /v1/tenant/assets``) — page-paginated
  (``page``/``perPage``/``meta.hasNextPage``; the response envelope has no
  ``cursor`` field at all for this endpoint).
- ``vulnerabilities`` (``GET /v1/tenant/vulnerabilities``) — accepts both
  ``page`` and ``cursor`` as query params; page-paginated here for
  consistency with ``assets`` (increment ``page`` while
  ``meta.hasNextPage`` is true) rather than mixing cursor- and page-driven
  continuation across resources.

**Caveat:** ``MANIFEST`` column paths were built from Plerion's public API
reference (https://docs.plerion.com/api-reference), not a live schema
introspection against a real tenant — same caveat tier as ``wiz.py``,
``appomni.py``, and most other collectors in this codebase. Verify field
names against a real tenant's response before relying on this collector.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger = logging.getLogger("posture.collectors.plerion")

_PAGE_SIZE = 100

MANIFEST: dict[str, dict[str, Any]] = {
    "findings": {
        "columns": {
            "id": ("id", "str"),
            "integration_id": ("integrationId", "str"),
            "provider": ("provider", "str"),
            "provider_account_id": ("providerAccountId", "str"),
            "asset_id": ("assetId", "str"),
            "resource_type": ("resourceType", "str"),
            "resource_id": ("resourceId", "str"),
            "full_resource_name": ("fullResourceName", "str"),
            "resource_url": ("resourceURL", "str"),
            "region": ("region", "str"),
            "service": ("service", "str"),
            "detection_id": ("detectionId", "str"),
            "status": ("status", "str"),
            "message": ("message", "str"),
            "severity_level": ("severityLevel", "str"),
            "modified_severity_level": ("modifiedSeverityLevel", "str"),
            "likelihood": ("likelihood", "str"),
            "impact": ("impact", "str"),
            "calculated_severity": ("calculatedSeverity", "str"),
            "is_exempted": ("isExempted", "bool"),
            "first_observed_at": ("firstObservedAt", "datetime"),
            "last_observed_at": ("lastObservedAt", "datetime"),
            "created_at": ("createdAt", "datetime"),
            "updated_at": ("updatedAt", "datetime"),
            "sla_due_at": ("slaDueAt", "datetime"),
            "sla_warn_at": ("slaWarnAt", "datetime"),
            "tags": ("tags", "json"),
            "resource_tags": ("resourceTags", "json"),
            "parameters": ("parameters", "json"),
            "attack_paths": ("attackPaths", "json"),
        }
    },
    "assets": {
        "columns": {
            "id": ("id", "str"),
            "integration_id": ("integrationId", "str"),
            "provider": ("provider", "str"),
            "provider_account_id": ("providerAccountId", "str"),
            "type": ("type", "str"),
            "name": ("name", "str"),
            "resource_type": ("resourceType", "str"),
            "resource_id": ("resourceId", "str"),
            "resource_name": ("resourceName", "str"),
            "full_resource_name": ("fullResourceName", "str"),
            "resource_url": ("resourceURL", "str"),
            "region": ("region", "str"),
            "service": ("service", "str"),
            "operational_state": ("operationalState", "str"),
            "operating_system": ("operatingSystem", "str"),
            "platform": ("platform", "str"),
            "first_observed_at": ("firstObservedAt", "datetime"),
            "last_observed_at": ("lastObservedAt", "datetime"),
            "created_at": ("createdAt", "datetime"),
            "updated_at": ("updatedAt", "datetime"),
            "last_scanned_at": ("lastScannedAt", "datetime"),
            "is_publicly_exposed": ("isPubliclyExposed", "bool"),
            "is_vulnerable": ("isVulnerable", "bool"),
            "has_kev": ("hasKev", "bool"),
            "has_exploit": ("hasExploit", "bool"),
            "is_exploitable": ("isExploitable", "bool"),
            "has_admin_privileges": ("hasAdminPrivileges", "bool"),
            "has_overly_permissive_privileges": (
                "hasOverlyPermissivePrivileges",
                "bool",
            ),
            "risk_score": ("riskScore", "float"),
            "vulnerability_score": ("vulnerabilityScore", "float"),
            "number_of_critical_vulnerabilities": (
                "numberOfCriticalVulnerabilities",
                "int",
            ),
            "number_of_high_vulnerabilities": ("numberOfHighVulnerabilities", "int"),
            "number_of_medium_vulnerabilities": (
                "numberOfMediumVulnerabilities",
                "int",
            ),
            "number_of_low_vulnerabilities": ("numberOfLowVulnerabilities", "int"),
            "number_of_critical_secrets": ("numberOfCriticalSecrets", "int"),
            "number_of_high_secrets": ("numberOfHighSecrets", "int"),
            "number_of_medium_secrets": ("numberOfMediumSecrets", "int"),
            "number_of_low_secrets": ("numberOfLowSecrets", "int"),
            "tags": ("tags", "json"),
            "resource_tags": ("resourceTags", "json"),
        }
    },
    "vulnerabilities": {
        "columns": {
            "asset_id": ("assetId", "str"),
            "integration_id": ("integrationId", "str"),
            "provider": ("provider", "str"),
            "asset_type": ("assetType", "str"),
            "vulnerability_id": ("vulnerabilityId", "str"),
            "title": ("title", "str"),
            "description": ("description", "str"),
            "severity_level": ("severityLevel", "str"),
            "severity_level_value": ("severityLevelValue", "int"),
            "severity_source": ("severitySource", "str"),
            "target_name": ("targetName", "str"),
            "primary_url": ("primaryUrl", "str"),
            "has_kev": ("hasKev", "bool"),
            "has_exploit": ("hasExploit", "bool"),
            "has_vendor_fix": ("hasVendorFix", "bool"),
            "first_observed_at": ("firstObservedAt", "datetime"),
            "last_observed_at": ("lastObservedAt", "datetime"),
            "published_date": ("publishedDate", "datetime"),
            "packages": ("packages", "json"),
            "cwes": ("cwes", "json"),
            "known_exploit": ("knownExploit", "json"),
            "exploits": ("exploits", "json"),
            "exemptions": ("exemptions", "json"),
        }
    },
}


class PlerionCollector(Collector):
    env_prefix = "PLERION"
    display_name = "Plerion"
    manifest = MANIFEST
    url_config_keys = ("endpoint",)
    config_keys: ClassVar[dict[str, bool]] = {
        "endpoint": True,
        "api_key": True,
    }

    def _authenticate(self) -> None:
        self._session.headers["Authorization"] = f"Bearer {self._config['api_key']}"
        self._session.headers["Accept"] = "application/json"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "findings":
            return self._fetch_cursor_page("findings", kwargs, cursor)
        if resource in ("assets", "vulnerabilities"):
            return self._fetch_page_number_page(resource, kwargs, cursor)
        raise ValueError(f"Unknown resource '{resource}'")

    def _fetch_cursor_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        params: dict[str, Any] = {"perPage": _PAGE_SIZE}
        params.update(kwargs)
        if cursor:
            params["cursor"] = cursor

        payload = self._get(f"/v1/tenant/{resource}", params)
        meta = payload.get("meta", {})
        next_cursor = meta.get("cursor") if meta.get("hasNextPage") else None
        return payload.get("data", []), next_cursor

    def _fetch_page_number_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        page = cursor or 1
        params: dict[str, Any] = {"page": page, "perPage": _PAGE_SIZE}
        params.update(kwargs)
        params["page"] = page

        payload = self._get(f"/v1/tenant/{resource}", params)
        meta = payload.get("meta", {})
        next_page = page + 1 if meta.get("hasNextPage") else None
        return payload.get("data", []), next_page

    def _get(self, path: str, params: dict[str, Any]) -> dict[str, Any]:
        response = self._session.get(
            f"{self._config['endpoint']}{path}", params=params, timeout=30
        )
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitedSignal(
                retry_after=float(retry_after) if retry_after else None
            )
        if response.status_code == 401:
            raise UnauthorizedSignal()
        response.raise_for_status()
        return response.json()
