"""Snyk collector.

Raw ``requests`` against Snyk's REST API v3 (JSON:API envelope) plus one
v1 endpoint that has no REST equivalent (org members) — no vendor SDK.
Auth, retry (429/401/connection-error), and reporting come from the base
Collector.

``organizations`` is a real paginated top-level resource: REST v3's
``links.next`` is already a complete relative path (query string and all),
so the cursor threaded through ``_fetch_page`` *is* that path — the same
shape as ``appomni.py``'s DRF ``next`` URL, just relative instead of
absolute.

``members``, ``projects``, and ``issues`` are per-organisation: Snyk has no
"all orgs" endpoint for any of them, so each fans out one call (``members``,
a bare unpaginated v1 list) or one paginated loop (``projects``/``issues``,
REST v3) per org id across a thread pool — the same per-item fan-out shape
as ``knowbe4.py``'s ``pst_recipients`` (fan out, then paginate internally
per item), not a ``derived_from``/``record_path`` explosion, since org
members/projects/issues are each their own network call rather than data
nested inside the org list response. Org ids are read from ``organizations``
internally unless an ``org_ids`` kwarg is given. ``_org_id`` is injected
client-side into every member/project/issue record (see
``_fetch_all_for_org``).

Resources: ``organizations``, ``members``, ``projects``, ``issues``.

**Caveat:** ``MANIFEST`` column paths below were built from Snyk's public
API reference and a prior in-house extraction script, not a live schema
introspection against a real tenant — same caveat as ``wiz.py`` and
``appomni.py``. Verify field names/nesting against a real tenant's response
before relying on this collector, and correct ``MANIFEST`` if they don't
match.
"""

from __future__ import annotations

import concurrent.futures
import logging
import os
from typing import Any

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger = logging.getLogger("posture.collectors.snyk")

_DEFAULT_BASE_URL = "https://api.snyk.io"
_API_VERSION = "2024-08-25"
_PAGE_LIMIT = 100
_DEFAULT_ORG_FANOUT_MAX_WORKERS = 8

_ORGANIZATIONS_PATH = "/rest/orgs"
_MEMBERS_PATH = "/v1/org/{org_id}/members"
_PROJECTS_PATH = "/rest/orgs/{org_id}/projects"
_ISSUES_PATH = "/rest/orgs/{org_id}/issues"

MANIFEST: dict[str, dict[str, Any]] = {
    "organizations": {
        "endpoint": _ORGANIZATIONS_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("attributes.name", "str"),
            "slug": ("attributes.slug", "str"),
            "group_id": ("relationships.group.data.id", "str"),
        },
    },
    "members": {
        # Not derived_from "organizations": each org's members are their own
        # (unpaginated, v1) network call, fanned out across a thread pool —
        # not data nested inside the raw org record. _org_id is injected
        # client-side (see _fetch_all_for_org).
        "endpoint": _MEMBERS_PATH,
        "columns": {
            "org_id": ("_org_id", "str"),
            "id": ("id", "str"),
            "username": ("username", "str"),
            "name": ("name", "str"),
            "email": ("email", "str"),
            "role": ("role", "str"),
            "active": ("active", "bool"),
        },
    },
    "projects": {
        # Not derived_from "organizations": each org's projects are their own
        # paginated network call, fanned out across a thread pool. _org_id is
        # injected client-side (see _fetch_all_for_org).
        "endpoint": _PROJECTS_PATH,
        "columns": {
            "org_id": ("_org_id", "str"),
            "id": ("id", "str"),
            "name": ("attributes.name", "str"),
            "type": ("attributes.type", "str"),
            "origin": ("attributes.origin", "str"),
            "status": ("attributes.status", "str"),
            "created": ("attributes.created", "datetime"),
            "target_reference": ("attributes.target_reference", "str"),
            "business_criticality": ("attributes.business_criticality", "json"),
            "environment": ("attributes.environment", "json"),
            "lifecycle": ("attributes.lifecycle", "json"),
        },
    },
    "issues": {
        # Not derived_from "organizations": each org's issues are their own
        # paginated network call, fanned out across a thread pool. _org_id is
        # injected client-side (see _fetch_all_for_org).
        "endpoint": _ISSUES_PATH,
        "columns": {
            "org_id": ("_org_id", "str"),
            "id": ("id", "str"),
            "title": ("attributes.title", "str"),
            "type": ("attributes.type", "str"),
            "effective_severity_level": (
                "attributes.effective_severity_level",
                "str",
            ),
            "status": ("attributes.status", "str"),
            "ignored": ("attributes.ignored", "bool"),
            "created_at": ("attributes.created_at", "datetime"),
            "updated_at": ("attributes.updated_at", "datetime"),
            "project_id": ("relationships.scan_item.data.id", "str"),
        },
    },
}


class SnykCollector(Collector):
    env_prefix = "SNYK"
    display_name = "Snyk"
    manifest = MANIFEST
    required_config_keys = ("token",)

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._base_url = (
            (config or {}).get("endpoint")
            or os.environ.get("SNYK_ENDPOINT")
            or _DEFAULT_BASE_URL
        ).rstrip("/")

    def _authenticate(self) -> None:
        self._session.headers["Accept"] = "application/json"
        self._session.headers["Authorization"] = f"token {self._config['token']}"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "organizations":
            return self._fetch_organizations_page(kwargs, cursor)
        return self._fetch_org_fanout_page(resource, kwargs, cursor)

    def _fetch_organizations_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            # links.next is already a complete, pre-parameterised relative path.
            response = self._get(self._base_url + cursor)
        else:
            params: dict[str, Any] = {"version": _API_VERSION, "limit": _PAGE_LIMIT}
            params.update(kwargs)
            response = self._get(self._base_url + _ORGANIZATIONS_PATH, params=params)

        payload = response.json()
        records = payload.get("data", []) or []
        next_cursor = (payload.get("links") or {}).get("next")
        return records, next_cursor

    def _fetch_org_fanout_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # entire fan-out already completed on first call

        org_ids = kwargs.get("org_ids")
        if org_ids is None:
            raw_orgs = self._get_raw("organizations", {})
            org_ids = [org["id"] for org in raw_orgs if org.get("id") is not None]
        if not org_ids:
            return [], None

        max_workers = kwargs.get("max_workers", _DEFAULT_ORG_FANOUT_MAX_WORKERS)
        workers = max(1, min(max_workers, len(org_ids)))

        all_records: list[dict[str, Any]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(self._fetch_all_for_org, resource, org_id): org_id
                for org_id in org_ids
            }
            for future in concurrent.futures.as_completed(futures):
                all_records.extend(future.result())

        return all_records, None

    def _fetch_all_for_org(self, resource: str, org_id: str) -> list[dict[str, Any]]:
        if resource == "members":
            records = self._get(
                self._base_url + _MEMBERS_PATH.format(org_id=org_id),
                params={"includeGroupAdmins": "true"},
            ).json()
            if not isinstance(records, list):
                records = []
            for record in records:
                record["_org_id"] = org_id
            return records

        path = {"projects": _PROJECTS_PATH, "issues": _ISSUES_PATH}[resource].format(
            org_id=org_id
        )
        records: list[dict[str, Any]] = []
        next_path: str | None = path
        params: dict[str, Any] | None = {
            "version": _API_VERSION,
            "limit": _PAGE_LIMIT,
        }
        while next_path is not None:
            response = self._get(self._base_url + next_path, params=params)
            payload = response.json()
            page_records = payload.get("data", []) or []
            for record in page_records:
                record["_org_id"] = org_id
            records.extend(page_records)
            next_path = (payload.get("links") or {}).get("next")
            params = None  # next_path already carries its own query string
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
                extra={"source": "snyk", "status_code": response.status_code},
            )
        response.raise_for_status()
        return response
