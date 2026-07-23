"""SailPoint Identity Security Cloud (ISC) collector.

Raw ``requests`` against SailPoint's REST API v3 — generic OAuth2
client-credentials REST, nothing here needs vendor SDK machinery the base
class can't already generalise. Auth, retry, pagination, caching, and
reporting all come from the base Collector; this module only knows ISC's
endpoints and resource manifests.

Resources: ``identities``, ``accounts``, ``access_profiles``, ``roles``.
This targets Identity Security Cloud (the cloud SaaS product, formerly
IdentityNow) specifically — IdentityIQ (self-hosted) exposes a different API
and is out of scope here.

Auth and API base URL are tenant-specific (``https://<tenant>.api.identitynow.com``
or a region-specific variant) and not auto-discoverable, so ``base_url`` is
required config. The OAuth token endpoint lives on the same host
(``<base_url>/oauth/token``), unlike Wiz where auth and API are on separate
hosts.

Pagination is offset/limit (v3's standard REST pagination), not cursor-based:
each page's ``next`` offset is ``offset + limit``; pagination ends when a
page returns fewer than ``limit`` records.
"""

from __future__ import annotations

import logging
from typing import Any

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal
from posture.exceptions import AuthenticationError

logger = logging.getLogger("posture.collectors.sailpoint")

_IDENTITIES_PATH = "/v3/identities"
_ACCOUNTS_PATH = "/v3/accounts"
_ACCESS_PROFILES_PATH = "/v3/access-profiles"
_ROLES_PATH = "/v3/roles"

_PAGE_LIMIT = 250

_RESOURCE_PATHS = {
    "identities": _IDENTITIES_PATH,
    "accounts": _ACCOUNTS_PATH,
    "access_profiles": _ACCESS_PROFILES_PATH,
    "roles": _ROLES_PATH,
}

MANIFEST: dict[str, dict[str, Any]] = {
    "identities": {
        "endpoint": _IDENTITIES_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "display_name": ("displayName", "str"),
            "first_name": ("firstName", "str"),
            "last_name": ("lastName", "str"),
            "email": ("email", "str"),
            "created": ("created", "datetime"),
            "modified": ("modified", "datetime"),
            "synced": ("synced", "datetime"),
            "status": ("status", "str"),
            "is_manager": ("isManager", "bool"),
            "disabled": ("disabled", "bool"),
            "locked": ("locked", "bool"),
            "identity_profile_id": ("identityProfile.id", "str"),
            "identity_profile_name": ("identityProfile.name", "str"),
            "lifecycle_state_id": ("lifecycleState.id", "str"),
            "lifecycle_state_name": ("lifecycleState.name", "str"),
            "manager_id": ("manager.id", "str"),
            "manager_name": ("manager.name", "str"),
        },
    },
    "accounts": {
        "endpoint": _ACCOUNTS_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "native_identity": ("nativeIdentity", "str"),
            "identity_id": ("identityId", "str"),
            "source_id": ("sourceId", "str"),
            "created": ("created", "datetime"),
            "modified": ("modified", "datetime"),
            "authoritative": ("authoritative", "bool"),
            "disabled": ("disabled", "bool"),
            "locked": ("locked", "bool"),
            "system_account": ("systemAccount", "bool"),
            "uncorrelated": ("uncorrelated", "bool"),
            "manually_correlated": ("manuallyCorrelated", "bool"),
            "has_entitlements": ("hasEntitlements", "bool"),
        },
    },
    "access_profiles": {
        "endpoint": _ACCESS_PROFILES_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "description": ("description", "str"),
            "created": ("created", "datetime"),
            "modified": ("modified", "datetime"),
            "enabled": ("enabled", "bool"),
            "requestable": ("requestable", "bool"),
            "owner_id": ("owner.id", "str"),
            "owner_name": ("owner.name", "str"),
            "source_id": ("source.id", "str"),
            "source_name": ("source.name", "str"),
        },
    },
    "roles": {
        "endpoint": _ROLES_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "description": ("description", "str"),
            "created": ("created", "datetime"),
            "modified": ("modified", "datetime"),
            "enabled": ("enabled", "bool"),
            "requestable": ("requestable", "bool"),
            "owner_id": ("owner.id", "str"),
            "owner_name": ("owner.name", "str"),
        },
    },
}


class SailpointCollector(Collector):
    env_prefix = "SAILPOINT"
    display_name = "SailPoint Identity Security Cloud"
    manifest = MANIFEST
    required_config_keys = ("base_url", "client_id", "client_secret")

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        self._base_url = self._config["base_url"].rstrip("/")

    def _authenticate(self) -> None:
        response = self._session.post(
            f"{self._base_url}/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self._config["client_id"],
                "client_secret": self._config["client_secret"],
            },
            timeout=30,
        )
        if response.status_code == 401:
            raise AuthenticationError(
                "SailPoint rejected client credentials",
                source="sailpoint",
                hint="check SAILPOINT_CLIENT_ID / SAILPOINT_CLIENT_SECRET",
            )
        response.raise_for_status()

        token = response.json()["access_token"]
        self._session.headers["Authorization"] = f"Bearer {token}"
        self._session.headers["Accept"] = "application/json"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        path = _RESOURCE_PATHS.get(resource)
        if path is None:
            raise ValueError(f"Unsupported resource '{resource}'")

        offset = cursor or 0
        params: dict[str, Any] = {"limit": _PAGE_LIMIT, "offset": offset}
        params.update(kwargs)

        response = self._session.get(self._base_url + path, params=params, timeout=30)
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitedSignal(
                retry_after=float(retry_after) if retry_after else None
            )
        if response.status_code == 401:
            raise UnauthorizedSignal()
        if response.status_code != 200:
            logger.warning(
                "unexpected status code",
                extra={
                    "source": "sailpoint",
                    "resource": resource,
                    "status_code": response.status_code,
                },
            )
        response.raise_for_status()

        records = response.json()
        if not isinstance(records, list):
            records = []
        next_cursor = offset + _PAGE_LIMIT if len(records) == _PAGE_LIMIT else None
        return records, next_cursor
