"""AppOmni collector.

Raw ``requests`` against AppOmni's REST API — no vendor SDK, static bearer
token auth (no OAuth flow: the token is issued out-of-band in the AppOmni
console and passed straight through), same pattern as ``upguard.py``'s
``api_key`` header. The API base URL is tenant-specific
(``https://<instance>.appomni.com``) with no cross-tenant discovery
mechanism, so ``instance`` is required config alongside ``access_token``.

Pagination is DRF-style: each page returns ``{"results": [...], "next":
<full URL or null>}``. ``next`` is already a complete, pre-parameterised
URL, so the cursor threaded through ``_fetch_page`` *is* that URL — no
offset/limit bookkeeping needed once the first page is fetched.
``monitored_services`` is the one exception: it returns a bare JSON list
with no pagination envelope at all.

Resources: ``monitored_services``, ``policies``, ``open_policy_issues``,
``posture_policies``, ``unified_identities``. ``policies`` and
``posture_policies`` hit the same ``/policy/`` endpoint with different
default query filters (reference policies vs. monitored-service-config
policies) — not a derived resource, since each needs its own network call
with its own filter.

**Caveat:** ``MANIFEST`` column paths below were built from AppOmni's
public API reference and the field names used by a prior in-house
extraction script, not a live schema introspection against a real tenant.
Verify field names/nesting against a real tenant's response before relying
on this collector, and correct ``MANIFEST`` if they don't match — same
caveat as ``wiz.py``.
"""

from __future__ import annotations

import logging
from typing import Any

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger = logging.getLogger("posture.collectors.appomni")

_MONITORED_SERVICES_PATH = "/api/v1/core/monitoredservice"
_POLICY_PATH = "/api/v1/core/policy/"
_OPEN_POLICY_ISSUES_PATH = "/api/v1/core/ruleevent/"
_UNIFIED_IDENTITIES_PATH = "/api/v1/core/unifiedidentity/"

_RESOURCE_PATHS = {
    "monitored_services": _MONITORED_SERVICES_PATH,
    "policies": _POLICY_PATH,
    "open_policy_issues": _OPEN_POLICY_ISSUES_PATH,
    "posture_policies": _POLICY_PATH,
    "unified_identities": _UNIFIED_IDENTITIES_PATH,
}

# Default query params per resource, mirroring the prior extraction
# script's hardcoded query strings. kwargs always win over these when a
# key collides (locked decision 5 in ARCHITECTURE.md).
_RESOURCE_DEFAULT_PARAMS: dict[str, dict[str, Any]] = {
    "policies": {"limit": 25, "offset": 0, "is_reference": "true"},
    "posture_policies": {"filter.policyType": "monitored_service_config"},
    "unified_identities": {"ordering": "-num_users_linked", "limit": 50},
}

MANIFEST: dict[str, dict[str, Any]] = {
    "monitored_services": {
        "endpoint": _MONITORED_SERVICES_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "app_type": ("app_type", "str"),
            "instance_url": ("instance_url", "str"),
            "status": ("status", "str"),
            "created": ("created", "datetime"),
            "updated": ("updated", "datetime"),
        },
    },
    "policies": {
        "endpoint": _POLICY_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "description": ("description", "str"),
            "policy_type": ("policyType", "str"),
            "severity": ("severity", "str"),
            "is_reference": ("is_reference", "bool"),
            "enabled": ("enabled", "bool"),
            "created": ("created", "datetime"),
            "updated": ("updated", "datetime"),
        },
    },
    "open_policy_issues": {
        "endpoint": _OPEN_POLICY_ISSUES_PATH,
        "columns": {
            "id": ("id", "str"),
            "policy_id": ("policy.id", "str"),
            "policy_name": ("policy.name", "str"),
            "severity": ("severity", "str"),
            "status": ("status", "str"),
            "monitored_service_id": ("monitored_service.id", "str"),
            "monitored_service_name": ("monitored_service.name", "str"),
            "detected_at": ("created", "datetime"),
            "resolved_at": ("resolved", "datetime"),
        },
    },
    "posture_policies": {
        "endpoint": _POLICY_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "description": ("description", "str"),
            "policy_type": ("policyType", "str"),
            "severity": ("severity", "str"),
            "enabled": ("enabled", "bool"),
            "created": ("created", "datetime"),
            "updated": ("updated", "datetime"),
        },
    },
    "unified_identities": {
        "endpoint": _UNIFIED_IDENTITIES_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "email": ("email", "str"),
            "identity_type": ("identity_type", "str"),
            "num_users_linked": ("num_users_linked", "int"),
            "risk_score": ("risk_score", "float"),
            "created": ("created", "datetime"),
            "updated": ("updated", "datetime"),
        },
    },
}


class AppOmniCollector(Collector):
    env_prefix = "APPOMNI"
    display_name = "AppOmni"
    manifest = MANIFEST
    required_config_keys = ("access_token", "instance")

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._base_url = f"https://{self._config['instance']}.appomni.com"

    def _authenticate(self) -> None:
        self._session.headers["Accept"] = "application/json"
        self._session.headers["Authorization"] = (
            f"Bearer {self._config['access_token']}"
        )

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            # `next` is already a complete, pre-parameterised URL.
            response = self._get(cursor)
        else:
            path = _RESOURCE_PATHS[resource]
            params = dict(_RESOURCE_DEFAULT_PARAMS.get(resource, {}))
            params.update(kwargs)
            response = self._get(self._base_url + path, params=params)

        payload = response.json()
        if isinstance(payload, list):
            # monitored_services: no pagination envelope at all.
            return payload, None

        records = payload.get("results", []) or []
        next_cursor = payload.get("next")
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
                extra={
                    "source": "appomni",
                    "status_code": response.status_code,
                },
            )
        response.raise_for_status()
        return response
