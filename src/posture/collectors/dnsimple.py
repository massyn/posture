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

Resources:

- ``domains`` — one row per domain. page/per_page with a ``pagination``
  envelope (``total_pages``), the same shape as ``cloudflare.py``'s ``zones``.
- ``zone_records`` — one row per DNS record. DNSimple has no "all zones'
  records" endpoint, so this fans out one paginated
  ``GET /{account}/zones/{zone}/records`` call per zone across a thread pool
  — the same per-item fan-out shape as ``cloudflare.py``'s ``dns_records``.
  The zone name is the domain name; zone names are read from ``domains``
  internally (``requires``, not ``derived_from``: each zone's records are
  their own network call, not data nested in the domain list response)
  unless a ``zones`` kwarg (list of zone names) is given. A domain with no
  hosted zone (registration-only, DNS elsewhere) 404s and contributes no
  rows. ``_zone`` is injected client-side into every record.

The reference implementation this collector was ported from also did live
DNS resolution (MX/TXT/DMARC/DKIM lookups against a hardcoded public
resolver) per domain; that was deliberately left out here since it requires
a new dependency (``dnspython``) outside posture's approved dependency list
and isn't a DNSimple API response at all.

**Caveat:** ``MANIFEST`` column paths below were built from DNSimple's
public API reference, not a live schema introspection against a real
account — same caveat as ``wiz.py``, ``appomni.py``, ``snyk.py``, and
``cloudflare.py``. Verify field names/nesting against a real account's
response before relying on this collector, and correct ``MANIFEST`` if they
don't match.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal
from posture.exceptions import AuthenticationError

logger = logging.getLogger("posture.collectors.dnsimple")

_DEFAULT_BASE_URL = "https://api.dnsimple.com/v2/"
_WHOAMI_PATH = "whoami"
_DOMAINS_PATH = "{account_id}/domains"
_ZONE_RECORDS_PATH = "{account_id}/zones/{zone}/records"
_PAGE_SIZE = 100
_DEFAULT_ZONE_FANOUT_MAX_WORKERS = 10

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
    "zone_records": {
        # Not derived_from "domains": each zone's records are their own
        # network call, fanned out across a thread pool (see
        # _fetch_zone_records_fanout_page). requires="domains" so the domain
        # list's raw records are cached for the fan-out to read zone names
        # from. _zone is injected client-side.
        "requires": "domains",
        "endpoint": _ZONE_RECORDS_PATH,
        "columns": {
            "zone": ("_zone", "str"),
            "id": ("id", "str"),
            "zone_id": ("zone_id", "str"),
            "parent_id": ("parent_id", "str"),
            "name": ("name", "str"),
            "content": ("content", "str"),
            "type": ("type", "str"),
            "ttl": ("ttl", "int"),
            "priority": ("priority", "int"),
            "regions": ("regions", "str"),
            "system_record": ("system_record", "bool"),
            "created_at": ("created_at", "datetime"),
            "updated_at": ("updated_at", "datetime"),
        },
    },
}


class DnsimpleCollector(Collector):
    env_prefix = "DNSIMPLE"
    display_name = "DNSimple"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {"token": True, "endpoint": False}
    url_config_keys = ("endpoint",)

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        self._base_url = self._config["endpoint"]
        self._account_id: str | None = None

    def _resolve_config(self, explicit: dict[str, Any]) -> dict[str, Any]:
        resolved = super()._resolve_config(explicit)
        resolved["endpoint"] = self._normalize_url(
            resolved.get("endpoint") or _DEFAULT_BASE_URL
        )
        return resolved

    def _authenticate(self) -> None:
        self._session.headers["Authorization"] = f"Bearer {self._config['token']}"
        self._session.headers["Accept"] = "application/json"

        response = self._session.get(f"{self._base_url}/{_WHOAMI_PATH}", timeout=30)
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
        if resource == "domains":
            return self._fetch_domains_page(kwargs, cursor)
        return self._fetch_zone_records_fanout_page(kwargs, cursor)

    def _fetch_domains_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        page = cursor if cursor is not None else 1
        path = _DOMAINS_PATH.format(account_id=self._account_id)
        params: dict[str, Any] = {"page": page, "per_page": _PAGE_SIZE}
        params.update(kwargs)

        payload = self._get(f"{self._base_url}/{path}", params=params).json()

        records = payload.get("data", []) or []
        pagination = payload.get("pagination") or {}
        next_cursor = page + 1 if page < pagination.get("total_pages", page) else None
        return records, next_cursor

    def _fetch_zone_records_fanout_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # entire fan-out already completed on first call

        zones = kwargs.get("zones")
        if zones is None:
            zones = [
                domain["name"]
                for domain in self._get_raw("domains", {})
                if domain.get("name")
            ]
        zones = [zone for zone in zones if zone]
        if not zones:
            return [], None

        max_workers = kwargs.get("max_workers", _DEFAULT_ZONE_FANOUT_MAX_WORKERS)
        workers = max(1, min(max_workers, len(zones)))

        records = self._resumable_fanout(
            "zone_records",
            zones,
            self._fetch_records_for_zone,
            workers,
        )
        return records, None

    def _fetch_records_for_zone(self, zone: str) -> list[dict[str, Any]]:
        path = _ZONE_RECORDS_PATH.format(account_id=self._account_id, zone=zone)
        records: list[dict[str, Any]] = []
        page = 1
        while True:
            params = {"page": page, "per_page": _PAGE_SIZE}
            response = self._get(
                f"{self._base_url}/{path}", params=params, allow_404=True
            )
            if response.status_code == 404:
                return []  # domain has no hosted zone (DNS managed elsewhere)
            payload = response.json()

            page_records = payload.get("data", []) or []
            for record in page_records:
                record["_zone"] = zone
            records.extend(page_records)

            pagination = payload.get("pagination") or {}
            if page >= pagination.get("total_pages", page):
                break
            page += 1
        return records

    def _get(
        self,
        url: str,
        params: dict[str, Any] | None = None,
        *,
        allow_404: bool = False,
    ) -> Any:
        response = self._session.get(url, params=params, timeout=30)
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitedSignal(
                retry_after=float(retry_after) if retry_after else None
            )
        if response.status_code in (401, 403):
            raise UnauthorizedSignal()
        if allow_404 and response.status_code == 404:
            return response
        if response.status_code != 200:
            logger.warning(
                "unexpected status code",
                extra={"source": "dnsimple", "status_code": response.status_code},
            )
        response.raise_for_status()
        return response
