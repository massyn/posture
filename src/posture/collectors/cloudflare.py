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

``workers_routes`` is zone-scoped the same way (fanned out per zone id off
``zones``), but hits its own endpoint
(``/zones/{zone_id}/workers/routes``) and injects ``_zone_id``/
``_zone_name`` from the cached ``zones`` list itself (see
``_fetch_all_for_zone_generic``) rather than from the record body, since
(unlike the DNS API) Workers routes don't echo the zone's name back.

``pages_projects`` and ``workers_scripts`` are account-scoped, not
zone-scoped — Cloudflare has no "all accounts" endpoint either, so their
account id list is derived from the already-fetched ``zones`` (each zone
carries its account's id/name), deduplicated, and fanned out the same way
(see ``_fetch_account_fanout_page``/``_fetch_all_for_account``). A token
whose zones all belong to one account still gets every project/script that
account owns; a multi-account token gets all of them.

Resources: ``zones``, ``dns_records``, ``cdn_protected_domains``,
``workers_routes``, ``pages_projects``, ``workers_scripts``.

**Caveat:** ``MANIFEST`` column paths below were built from Cloudflare's
public API reference, not a live schema introspection against a real
tenant — same caveat as ``wiz.py``, ``appomni.py``, and ``snyk.py``.
Verify field names/nesting against a real tenant's response before relying
on this collector, and correct ``MANIFEST`` if they don't match.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger = logging.getLogger("posture.collectors.cloudflare")

_BASE_URL = "https://api.cloudflare.com/client/v4"
_PAGE_SIZE = 50
_DEFAULT_ZONE_FANOUT_MAX_WORKERS = 8

_ZONES_PATH = "/zones"
_DNS_RECORDS_PATH = "/zones/{zone_id}/dns_records"
_WORKERS_ROUTES_PATH = "/zones/{zone_id}/workers/routes"
_PAGES_PROJECTS_PATH = "/accounts/{account_id}/pages/projects"
_WORKERS_SCRIPTS_PATH = "/accounts/{account_id}/workers/scripts"

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
    "workers_routes": {
        # Zone-scoped fan-out, same shape as dns_records/cdn_protected_domains,
        # but its own endpoint — see _fetch_zone_generic_fanout_page.
        "requires": "zones",
        "endpoint": _WORKERS_ROUTES_PATH,
        "columns": {
            "zone_id": ("_zone_id", "str"),
            "zone_name": ("_zone_name", "str"),
            "id": ("id", "str"),
            "pattern": ("pattern", "str"),
            "script": ("script", "str"),
        },
    },
    "pages_projects": {
        # Account-scoped fan-out (see module docstring) — account ids
        # deduplicated from the cached zones list, not their own network
        # call. _account_id/_account_name are injected client-side.
        "requires": "zones",
        "endpoint": _PAGES_PROJECTS_PATH,
        "columns": {
            "account_id": ("_account_id", "str"),
            "account_name": ("_account_name", "str"),
            "id": ("id", "str"),
            "name": ("name", "str"),
            "subdomain": ("subdomain", "str"),
            "domains": ("domains", "json"),
            "production_branch": ("production_branch", "str"),
            "source_type": ("source.type", "str"),
            "source_config_owner": ("source.config.owner", "str"),
            "source_config_repo_name": ("source.config.repo_name", "str"),
            "created_on": ("created_on", "datetime"),
            "latest_deployment_id": ("latest_deployment.id", "str"),
            "latest_deployment_url": ("latest_deployment.url", "str"),
            "latest_deployment_environment": (
                "latest_deployment.environment",
                "str",
            ),
        },
    },
    "workers_scripts": {
        # Account-scoped fan-out, same mechanics as pages_projects.
        "requires": "zones",
        "endpoint": _WORKERS_SCRIPTS_PATH,
        "columns": {
            "account_id": ("_account_id", "str"),
            "account_name": ("_account_name", "str"),
            "id": ("id", "str"),
            "etag": ("etag", "str"),
            "created_on": ("created_on", "datetime"),
            "modified_on": ("modified_on", "datetime"),
            "usage_model": ("usage_model", "str"),
            "logpush": ("logpush", "bool"),
            "tags": ("tags", "json"),
        },
    },
}

_DNS_RECORD_RESOURCE_PARAMS: dict[str, dict[str, Any]] = {
    "dns_records": {},
    "cdn_protected_domains": {"proxied": "true"},
}

_ACCOUNT_RESOURCE_PATHS: dict[str, str] = {
    "pages_projects": _PAGES_PROJECTS_PATH,
    "workers_scripts": _WORKERS_SCRIPTS_PATH,
}


class CloudflareCollector(Collector):
    env_prefix = "CLOUDFLARE"
    display_name = "Cloudflare"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {"api_token": True}

    def _authenticate(self) -> None:
        self._session.headers["Accept"] = "application/json"
        self._session.headers["Authorization"] = f"Bearer {self._config['api_token']}"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "zones":
            return self._fetch_zones_page(kwargs, cursor)
        if resource in _DNS_RECORD_RESOURCE_PARAMS:
            return self._fetch_zone_fanout_page(resource, kwargs, cursor)
        if resource == "workers_routes":
            return self._fetch_zone_generic_fanout_page(
                resource, _WORKERS_ROUTES_PATH, kwargs, cursor
            )
        if resource in _ACCOUNT_RESOURCE_PATHS:
            return self._fetch_account_fanout_page(
                resource, _ACCOUNT_RESOURCE_PATHS[resource], kwargs, cursor
            )
        raise ValueError(f"Unsupported resource '{resource}'")

    def _fetch_zones_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        page = cursor if cursor is not None else 1
        params: dict[str, Any] = {"page": page, "per_page": _PAGE_SIZE}
        params.update(kwargs)
        payload = self._get_json(_BASE_URL + _ZONES_PATH, params=params)

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

        all_records = self._resumable_fanout(
            resource,
            zone_ids,
            lambda zone_id: self._fetch_all_for_zone(resource, zone_id),
            workers,
        )
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
            payload = self._get_json(_BASE_URL + path, params=params)

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

    def _fetch_zone_generic_fanout_page(
        self, resource: str, path_template: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # entire fan-out already completed on first call

        raw_zones = self._get_raw("zones", {})
        zone_names = {z["id"]: z.get("name") for z in raw_zones if z.get("id")}
        zone_ids = kwargs.get("zone_ids") or list(zone_names.keys())
        if not zone_ids:
            return [], None

        max_workers = kwargs.get("max_workers", _DEFAULT_ZONE_FANOUT_MAX_WORKERS)
        workers = max(1, min(max_workers, len(zone_ids)))

        all_records = self._resumable_fanout(
            resource,
            zone_ids,
            lambda zone_id: self._fetch_all_for_zone_generic(
                path_template, zone_id, zone_names.get(zone_id)
            ),
            workers,
        )
        return all_records, None

    def _fetch_all_for_zone_generic(
        self, path_template: str, zone_id: str, zone_name: str | None
    ) -> list[dict[str, Any]]:
        path = path_template.format(zone_id=zone_id)
        records: list[dict[str, Any]] = []
        page = 1
        while True:
            params = {"page": page, "per_page": _PAGE_SIZE}
            payload = self._get_json(_BASE_URL + path, params=params)

            page_records = payload.get("result", []) or []
            for record in page_records:
                record["_zone_id"] = zone_id
                record["_zone_name"] = zone_name
            records.extend(page_records)

            result_info = payload.get("result_info") or {}
            if page >= result_info.get("total_pages", page):
                break
            page += 1
        return records

    def _fetch_account_fanout_page(
        self, resource: str, path_template: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # entire fan-out already completed on first call

        account_names: dict[str, str | None] = {}
        raw_zones = self._get_raw("zones", {})
        for zone in raw_zones:
            account = zone.get("account") or {}
            account_id = account.get("id")
            if account_id and account_id not in account_names:
                account_names[account_id] = account.get("name")
        account_ids = kwargs.get("account_ids") or list(account_names.keys())
        if not account_ids:
            return [], None

        max_workers = kwargs.get("max_workers", _DEFAULT_ZONE_FANOUT_MAX_WORKERS)
        workers = max(1, min(max_workers, len(account_ids)))

        all_records = self._resumable_fanout(
            resource,
            account_ids,
            lambda account_id: self._fetch_all_for_account(
                path_template, account_id, account_names.get(account_id)
            ),
            workers,
        )
        return all_records, None

    def _fetch_all_for_account(
        self, path_template: str, account_id: str, account_name: str | None
    ) -> list[dict[str, Any]]:
        path = path_template.format(account_id=account_id)
        records: list[dict[str, Any]] = []
        page = 1
        while True:
            params = {"page": page, "per_page": _PAGE_SIZE}
            payload = self._get_json(_BASE_URL + path, params=params)

            page_records = payload.get("result", []) or []
            for record in page_records:
                record["_account_id"] = account_id
                record["_account_name"] = account_name
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

    def _get_json(
        self, url: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """GET and parse the Cloudflare v4 envelope, treating ``success: false``
        as a failure.

        Cloudflare returns HTTP 200 even for logical failures (bad token
        scope, invalid params, etc.) — the outcome lives in the JSON body's
        ``success``/``errors`` fields, with ``result`` coming back ``null``.
        Without this check such a failure looks identical to "zero records",
        so the collector silently reports an empty resource instead of
        surfacing the error.
        """
        payload = self._get(url, params=params).json()
        if payload.get("success") is False:
            errors = payload.get("errors") or []
            detail = (
                "; ".join(
                    str(err.get("message", err)) if isinstance(err, dict) else str(err)
                    for err in errors
                )
                or "no error detail returned"
            )
            raise RuntimeError(f"Cloudflare API request failed: {detail}")
        return payload
