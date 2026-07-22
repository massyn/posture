"""DNSimple collector.

Raw ``requests`` against DNSimple's REST API v2 — no vendor SDK, static
bearer token auth (``Authorization: Bearer <token>``), same "just set the
header" shape as AppOmni/Snyk/Cloudflare. Every DNSimple v2 endpoint is
scoped under an account id that isn't known up front, so ``_authenticate``
calls ``whoami`` once to discover it and caches it on the instance for every
subsequent request — the same "discover, then route" shape as Crowdstrike's
cloud-region lookup, just returning an account id instead of a base URL.
The API base URL defaults to DNSimple's production endpoint
(``https://api.dnsimple.com/v2/``) but is overridable via ``endpoint``
config, since DNSimple also runs a sandbox environment at a different host.

Resources: ``domains``.

**Caveat:** ``MANIFEST`` column paths below were built from DNSimple's
public API reference, not a live schema introspection against a real
account — same caveat as ``wiz.py``, ``appomni.py``, ``snyk.py``, and
``cloudflare.py``. Verify field names/nesting against a real account's
response before relying on this collector, and correct ``MANIFEST`` if they
don't match.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal
from posture.exceptions import AuthenticationError

logger = logging.getLogger("posture.collectors.dnsimple")

_DEFAULT_BASE_URL = "https://api.dnsimple.com/v2/"
_WHOAMI_PATH = "whoami"
_DOMAINS_PATH = "{account_id}/domains"
_PAGE_SIZE = 100

MANIFEST: dict[str, dict[str, Any]] = {
    "domains": {
        "endpoint": _DOMAINS_PATH,
        "columns": {
            "id": ("id", "str"),
            "account_id": ("account_id", "str"),
            "registrant_id": ("registrant_id", "str"),
            "name": ("name", "str"),
            "unicode_name": ("unicode_name", "str"),
            "state": ("state", "str"),
            "auto_renew": ("auto_renew", "bool"),
            "private_whois": ("private_whois", "bool"),
            "expires_on": ("expires_on", "datetime"),
            "expires_at": ("expires_at", "datetime"),
            "created_at": ("created_at", "datetime"),
            "updated_at": ("updated_at", "datetime"),
        },
    },
}


class DnsimpleCollector(Collector):
    env_prefix = "DNSIMPLE"
    display_name = "DNSimple"
    manifest = MANIFEST
    required_config_keys = ("token",)

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._base_url = self._config["endpoint"]
        self._account_id: str | None = None

    def _resolve_config(self, explicit: dict[str, Any]) -> dict[str, Any]:
        resolved = super()._resolve_config(explicit)
        resolved["endpoint"] = explicit.get(
            "endpoint", os.environ.get("DNSIMPLE_ENDPOINT", _DEFAULT_BASE_URL)
        )
        return resolved

    def _authenticate(self) -> None:
        self._session.headers["Authorization"] = f"Bearer {self._config['token']}"
        self._session.headers["Accept"] = "application/json"

        response = self._session.get(self._base_url + _WHOAMI_PATH, timeout=30)
        if response.status_code == 401:
            raise AuthenticationError(
                "DNSimple rejected the API token",
                source="dnsimple",
                hint="check DNSIMPLE_TOKEN",
            )
        response.raise_for_status()

        account = response.json().get("data", {}).get("account")
        if account is None:
            raise AuthenticationError(
                "DNSimple token is not associated with an account",
                source="dnsimple",
                hint="check DNSIMPLE_TOKEN is an account (not user) token",
            )
        self._account_id = str(account["id"])

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        page = cursor if cursor is not None else 1
        path = _DOMAINS_PATH.format(account_id=self._account_id)
        params: dict[str, Any] = {"page": page, "per_page": _PAGE_SIZE}
        params.update(kwargs)

        response = self._session.get(self._base_url + path, params=params, timeout=30)
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
                extra={"source": "dnsimple", "status_code": response.status_code},
            )
        response.raise_for_status()
        payload = response.json()

        records = payload.get("data", []) or []
        pagination = payload.get("pagination") or {}
        next_cursor = page + 1 if page < pagination.get("total_pages", page) else None
        return records, next_cursor
