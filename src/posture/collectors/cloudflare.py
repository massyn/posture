"""Cloudflare collector.

Raw ``requests`` against Cloudflare's REST API v4 — no vendor SDK, static
API token auth (``Authorization: Bearer <token>``), same "just set the
header" shape as AppOmni/Snyk. The API base URL is global
(``https://api.cloudflare.com/client/v4``) — no tenant subdomain or
cross-tenant discovery mechanism; the token itself is scoped to whatever
zones it was issued against.

``zones`` is the only real top-level paginated resource — page/per_page
with a ``result_info`` envelope (``page``, ``per_page``, ``total_pages``).
Cloudflare has no "all zones' records" endpoint, so ``dns_records`` and
``cdn_protected_domains`` each fan out one paginated call per zone id
across a thread pool — the same per-item fan-out shape as ``snyk.py``'s
``projects``/``issues``. Zone ids are read from ``zones`` internally
unless a ``zone_ids`` kwarg is given (``requires``, not ``derived_from``:
each zone's records are their own network call, not data nested in the
zone list response).

``dns_records`` and ``cdn_protected_domains`` hit the same
``/zones/{zone_id}/dns_records`` endpoint with different default query
filters — ``cdn_protected_domains`` passes ``proxied=true`` server-side
(Cloudflare's own filter, not a client-side one) to return only records
proxied through Cloudflare's CDN — the same "same endpoint, different
default filter" shape as ``appomni.py``'s ``policies``/``posture_policies``.
``_zone_id`` and ``_zone_name`` are injected client-side into every DNS
record (see ``_fetch_all_for_zone``).

Resources: ``zones``, ``dns_records``, ``cdn_protected_domains``.

**Caveat:** ``MANIFEST`` column paths below were built from Cloudflare's
public API reference, not a live schema introspection against a real
tenant — same caveat as ``wiz.py``, ``appomni.py``, and ``snyk.py``.
Verify field names/nesting against a real tenant's response before relying
on this collector, and correct ``MANIFEST`` if they don't match.
"""

from __future__ import annotations

import concurrent.futures
import logging
from typing import Any

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger = logging.getLogger("posture.collectors.cloudflare")

_BASE_URL = "https://api.cloudflare.com/client/v4"
_PAGE_SIZE = 50
_DEFAULT_ZONE_FANOUT_MAX_WORKERS = 8

_ZONES_PATH = "/zones"
_DNS_RECORDS_PATH = "/zones/{zone_id}/dns_records"

MANIFEST: dict[str, dict[str, Any]] = {
    "zones": {
        "endpoint": _ZONES_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "status": ("status", "str"),
            "paused": ("paused", "bool"),
            "type": ("type", "str"),
            "development_mode": ("development_mode", "int"),
            "name_servers": ("name_servers", "json"),
            "original_name_servers": ("original_name_servers", "json"),
            "account_id": ("account.id", "str"),
            "account_name": ("account.name", "str"),
            "plan_name": ("plan.name", "str"),
            "created_on": ("created_on", "datetime"),
            "modified_on": ("modified_on", "datetime"),
            "activated_on": ("activated_on", "datetime"),
        },
    },
    "dns_records": {
        # Not derived_from "zones": each zone's DNS records are their own
        # paginated network call, fanned out across a thread pool.
        # _zone_id/_zone_name are injected client-side (see
        # _fetch_all_for_zone). requires="zones" so the zone id list is
        # cached across dns_records and cdn_protected_domains.
        "requires": "zones",
        "endpoint": _DNS_RECORDS_PATH,
        "columns": {
            "zone_id": ("_zone_id", "str"),
            "zone_name": ("_zone_name", "str"),
            "id": ("id", "str"),
            "name": ("name", "str"),
            "type": ("type", "str"),
            "content": ("content", "str"),
            "ttl": ("ttl", "int"),
            "proxiable": ("proxiable", "bool"),
            "proxied": ("proxied", "bool"),
            "locked": ("locked", "bool"),
            "comment": ("comment", "str"),
            "tags": ("tags", "json"),
            "created_on": ("created_on", "datetime"),
            "modified_on": ("modified_on", "datetime"),
        },
    },
    "cdn_protected_domains": {
        # Same endpoint as dns_records, filtered server-side to
        # proxied=true records only (the domains actually routed through
        # Cloudflare's CDN) — not derived_from, since it needs its own
        # network call with its own filter, same shape as appomni.py's
        # policies/posture_policies pair.
        "requires": "zones",
        "endpoint": _DNS_RECORDS_PATH,
        "columns": {
            "zone_id": ("_zone_id", "str"),
            "zone_name": ("_zone_name", "str"),
            "id": ("id", "str"),
            "name": ("name", "str"),
            "type": ("type", "str"),
            "content": ("content", "str"),
            "ttl": ("ttl", "int"),
            "proxied": ("proxied", "bool"),
            "created_on": ("created_on", "datetime"),
            "modified_on": ("modified_on", "datetime"),
        },
    },
}

_DNS_RECORD_RESOURCE_PARAMS: dict[str, dict[str, Any]] = {
    "dns_records": {},
    "cdn_protected_domains": {"proxied": "true"},
}


class CloudflareCollector(Collector):
    env_prefix = "CLOUDFLARE"
    display_name = "Cloudflare"
    manifest = MANIFEST
    required_config_keys = ("api_token",)

    def _authenticate(self) -> None:
        self._session.headers["Accept"] = "application/json"
        self._session.headers["Authorization"] = f"Bearer {self._config['api_token']}"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "zones":
            return self._fetch_zones_page(kwargs, cursor)
        return self._fetch_zone_fanout_page(resource, kwargs, cursor)

    def _fetch_zones_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        page = cursor if cursor is not None else 1
        params: dict[str, Any] = {"page": page, "per_page": _PAGE_SIZE}
        params.update(kwargs)
        response = self._get(_BASE_URL + _ZONES_PATH, params=params)
        payload = response.json()

        records = payload.get("result", []) or []
        result_info = payload.get("result_info") or {}
        next_cursor = page + 1 if page < result_info.get("total_pages", page) else None
        return records, next_cursor

    def _fetch_zone_fanout_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # entire fan-out already completed on first call

        zone_ids = kwargs.get("zone_ids")
        if zone_ids is None:
            raw_zones = self._get_raw("zones", {})
            zone_ids = [zone["id"] for zone in raw_zones if zone.get("id") is not None]
        if not zone_ids:
            return [], None

        max_workers = kwargs.get("max_workers", _DEFAULT_ZONE_FANOUT_MAX_WORKERS)
        workers = max(1, min(max_workers, len(zone_ids)))

        all_records: list[dict[str, Any]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(self._fetch_all_for_zone, resource, zone_id)
                for zone_id in zone_ids
            ]
            for future in concurrent.futures.as_completed(futures):
                all_records.extend(future.result())

        return all_records, None

    def _fetch_all_for_zone(self, resource: str, zone_id: str) -> list[dict[str, Any]]:
        path = _DNS_RECORDS_PATH.format(zone_id=zone_id)
        base_params = dict(_DNS_RECORD_RESOURCE_PARAMS[resource])

        records: list[dict[str, Any]] = []
        page = 1
        zone_name: str | None = None
        while True:
            params = dict(base_params)
            params["page"] = page
            params["per_page"] = _PAGE_SIZE
            response = self._get(_BASE_URL + path, params=params)
            payload = response.json()

            page_records = payload.get("result", []) or []
            for record in page_records:
                record["_zone_id"] = zone_id
                if zone_name is None and record.get("zone_name"):
                    zone_name = record["zone_name"]
                record["_zone_name"] = record.get("zone_name") or zone_name
            records.extend(page_records)

            result_info = payload.get("result_info") or {}
            if page >= result_info.get("total_pages", page):
                break
            page += 1
        return records

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
                extra={"source": "cloudflare", "status_code": response.status_code},
            )
        response.raise_for_status()
        return response
