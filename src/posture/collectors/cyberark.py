"""CyberArk Privileged Access Manager collector.

Raw ``requests`` against the PAM web services (``{base_url}/PasswordVault/API``),
no vendor SDK. One collector for both deployments — the ``/PasswordVault/API``
surface is the same; only authentication differs, chosen by config:

- **Privilege Cloud (ISPSS)** — ``identity_url`` set: ``username``/``password``
  are an Identity service user configured as an OAuth confidential client,
  exchanged at ``{identity_url}/oauth2/platformtoken`` (client credentials) for
  a bearer token. ``expires_in`` drives the base class's proactive refresh.
  ``identity_url`` is its own key because the Identity tenant id often differs
  from the Privilege Cloud subdomain and can't be derived from ``base_url``.
- **Self-hosted PVWA / Privilege Cloud Standard** — ``identity_url`` unset:
  ``POST /PasswordVault/API/auth/{logon_type}/Logon`` (``logon_type``
  ``CyberArk`` by default, or ``LDAP``/``RADIUS``/``Windows``) returns a
  session token sent bare in ``Authorization``. ``concurrentSession`` keeps
  the collector from ending the same user's other sessions. PVWA expires
  sessions on inactivity; the resulting 401 re-authenticates via
  ``UnauthorizedSignal``.

TLS: self-hosted PVWAs commonly present an internal-CA certificate, so the
shared ``ca_bundle``/``insecure`` options apply (``collectors/_tls.py``).

Passwords are never retrieved — no resource calls a ``/Password/Retrieve``
or secret endpoint; ``accounts`` reads only account metadata.

Resources:

- ``accounts`` and ``safes`` — ``limit``/``offset`` pages carrying a
  ``nextLink`` (relative to ``/PasswordVault/``). ``nextLink`` is followed
  rather than counting against ``count``, which integrators report as
  unreliable for accounts.
- ``safe_members`` — one ``/Safes/{safeUrlId}/Members`` call (itself
  ``nextLink``-paginated) per safe from ``safes`` (``requires``, so the safe
  list is cached), fanned out via ``_resumable_fanout``. One row per safe ×
  member, with the access-relevant permission flags as columns and the full
  permission set as JSON.

kwargs: passed through as query parameters on ``accounts``/``safes``
(e.g. ``search``, ``filter="safeName eq Finance"``), overriding the
defaults. ``safe_members`` takes none.

**Caveat:** built from CyberArk's public API references and third-party
integration documentation; no live tenant was available. Field names and the
``nextLink`` shape need verifying against a real deployment. The service
user only sees safes it is a member of (with List Accounts / View Safe
Members permissions), so its safe membership bounds the snapshot.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar
from urllib.parse import quote

from posture.base import (
    Collector,
    PermissionDeniedSignal,
    RateLimitedSignal,
    UnauthorizedSignal,
)
from posture.collectors._tls import resolve_verify
from posture.exceptions import AuthenticationError

logger = logging.getLogger("posture.collectors.cyberark")

_API_ROOT = "/PasswordVault/"
_PAGE_SIZE = 1000
_REQUEST_TIMEOUT_SECONDS = 120
_SAFE_MEMBERS_WORKERS = 8
# Case-insensitive config value -> the casing the Logon URL path expects.
_LOGON_TYPES = {
    "cyberark": "CyberArk",
    "ldap": "LDAP",
    "radius": "RADIUS",
    "windows": "Windows",
}

_LIST_PATHS = {"accounts": "API/Accounts", "safes": "API/Safes"}

MANIFEST: dict[str, dict[str, Any]] = {
    "accounts": {
        "endpoint": _API_ROOT + _LIST_PATHS["accounts"],
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "address": ("address", "str"),
            "user_name": ("userName", "str"),
            "platform_id": ("platformId", "str"),
            "safe_name": ("safeName", "str"),
            "secret_type": ("secretType", "str"),
            "automatic_management_enabled": (
                "secretManagement.automaticManagementEnabled",
                "bool",
            ),
            "manual_management_reason": (
                "secretManagement.manualManagementReason",
                "str",
            ),
            "management_status": ("secretManagement.status", "str"),
            "last_modified": ("secretManagement.lastModifiedTime", "datetime"),
            "last_reconciled": ("secretManagement.lastReconciledTime", "datetime"),
            "last_verified": ("secretManagement.lastVerifiedTime", "datetime"),
            "platform_account_properties": ("platformAccountProperties", "json"),
            "created": ("createdTime", "datetime"),
        },
    },
    "safes": {
        "endpoint": _API_ROOT + _LIST_PATHS["safes"],
        "columns": {
            "safe_url_id": ("safeUrlId", "str"),
            "safe_name": ("safeName", "str"),
            "safe_number": ("safeNumber", "int"),
            "description": ("description", "str"),
            "location": ("location", "str"),
            "creator_name": ("creator.name", "str"),
            "managing_cpm": ("managingCPM", "str"),
            "olac_enabled": ("olacEnabled", "bool"),
            "number_of_versions_retention": ("numberOfVersionsRetention", "int"),
            "number_of_days_retention": ("numberOfDaysRetention", "int"),
            "auto_purge_enabled": ("autoPurgeEnabled", "bool"),
            "created": ("creationTime", "datetime"),
            "last_modified": ("lastModificationTime", "datetime"),
        },
    },
    "safe_members": {
        "endpoint": _API_ROOT + "API/Safes/{safeUrlId}/Members",
        "requires": "safes",
        "columns": {
            "safe_url_id": ("safeUrlId", "str"),
            "safe_name": ("safeName", "str"),
            "member_id": ("memberId", "str"),
            "member_name": ("memberName", "str"),
            "member_type": ("memberType", "str"),
            "is_predefined_user": ("isPredefinedUser", "bool"),
            "is_read_only": ("isReadOnly", "bool"),
            "membership_expiration": ("membershipExpirationDate", "datetime"),
            "use_accounts": ("permissions.useAccounts", "bool"),
            "retrieve_accounts": ("permissions.retrieveAccounts", "bool"),
            "list_accounts": ("permissions.listAccounts", "bool"),
            "manage_safe": ("permissions.manageSafe", "bool"),
            "manage_safe_members": ("permissions.manageSafeMembers", "bool"),
            "access_without_confirmation": (
                "permissions.accessWithoutConfirmation",
                "bool",
            ),
            "permissions": ("permissions", "json"),
        },
    },
}


class CyberarkCollector(Collector):
    env_prefix = "CYBERARK"
    display_name = "CyberArk Privileged Access Manager"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {
        "base_url": True,
        "username": True,
        "password": True,
        "identity_url": False,
        "logon_type": False,
        "ca_bundle": False,
        "insecure": False,
    }
    url_config_keys: tuple[str, ...] = ("base_url", "identity_url")

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        self._api_root = self._config["base_url"] + _API_ROOT
        self._verify = resolve_verify(self._config, self.env_prefix)
        logon_type = str(self._config.get("logon_type", "CyberArk"))
        if logon_type.lower() not in _LOGON_TYPES:
            raise ValueError(
                f"Invalid 'logon_type' {logon_type!r}: expected one of "
                f"{sorted(_LOGON_TYPES.values())} (env var CYBERARK_LOGON_TYPE)"
            )
        self._logon_type = _LOGON_TYPES[logon_type.lower()]

    def _authenticate(self) -> None:
        self._session.headers["Accept"] = "application/json"
        if "identity_url" in self._config:
            self._authenticate_platform_token()
        else:
            self._authenticate_logon()

    def _authenticate_platform_token(self) -> None:
        response = self._session.post(
            self._config["identity_url"] + "/oauth2/platformtoken",
            data={
                "grant_type": "client_credentials",
                "client_id": self._config["username"],
                "client_secret": self._config["password"],
            },
            timeout=_REQUEST_TIMEOUT_SECONDS,
            verify=self._verify,
        )
        self._raise_for_auth_failure(response, "Identity platform token")
        token = response.json()
        self._session.headers["Authorization"] = f"Bearer {token['access_token']}"
        self._token_expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=int(token.get("expires_in", 1800))
        )

    def _authenticate_logon(self) -> None:
        response = self._session.post(
            f"{self._api_root}API/auth/{self._logon_type}/Logon",
            json={
                "username": self._config["username"],
                "password": self._config["password"],
                "concurrentSession": True,
            },
            timeout=_REQUEST_TIMEOUT_SECONDS,
            verify=self._verify,
        )
        self._raise_for_auth_failure(response, f"PVWA {self._logon_type} logon")
        # The Logon API returns the session token as a bare JSON string, sent
        # back as-is (no "Bearer" scheme).
        self._session.headers["Authorization"] = response.json()

    @staticmethod
    def _raise_for_auth_failure(response: Any, method: str) -> None:
        if response.status_code in (400, 401, 403):
            raise AuthenticationError(
                f"CyberArk {method} failed (HTTP {response.status_code})",
                source="cyberark",
                hint="check CYBERARK_USERNAME/CYBERARK_PASSWORD; for Privilege "
                "Cloud, also CYBERARK_IDENTITY_URL and that the user is an OAuth "
                "confidential client",
            )
        response.raise_for_status()

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource in _LIST_PATHS:
            if cursor is None:
                return self._get_page(
                    _LIST_PATHS[resource], {"limit": _PAGE_SIZE, **kwargs}
                )
            return self._get_page(cursor, None)
        if resource == "safe_members":
            if kwargs:
                raise ValueError(
                    f"Unsupported kwargs for 'safe_members': {sorted(kwargs)}"
                )
            safe_ids = [safe["safeUrlId"] for safe in self._get_raw("safes", {})]
            records = self._resumable_fanout(
                "safe_members", safe_ids, self._get_safe_members, _SAFE_MEMBERS_WORKERS
            )
            return records, None
        raise ValueError(f"Unsupported resource '{resource}'")

    def _get_safe_members(self, safe_url_id: str) -> list[dict[str, Any]]:
        members, next_link = self._get_page(
            f"API/Safes/{quote(safe_url_id, safe='')}/Members", {"limit": _PAGE_SIZE}
        )
        while next_link is not None:
            page, next_link = self._get_page(next_link, None)
            members.extend(page)
        return members

    def _get_page(
        self, path: str, params: dict[str, Any] | None
    ) -> tuple[list[dict[str, Any]], str | None]:
        """GET one ``{value, nextLink}`` page. ``path`` (and any ``nextLink``)
        is relative to ``/PasswordVault/``, though an absolute ``nextLink`` is
        followed as-is."""
        url = path if path.startswith("https://") else self._api_root + path.lstrip("/")
        response = self._session.get(
            url,
            params=params,
            timeout=_REQUEST_TIMEOUT_SECONDS,
            verify=self._verify,
        )
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitedSignal(
                retry_after=float(retry_after) if retry_after else None
            )
        if response.status_code == 401:
            raise UnauthorizedSignal()
        if response.status_code == 403:
            raise PermissionDeniedSignal(
                f"CyberArk denied {path}: {response.text[:200]}"
            )
        response.raise_for_status()
        body = response.json()
        return body.get("value") or [], body.get("nextLink") or None
