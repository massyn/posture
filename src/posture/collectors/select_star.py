"""Select Star collector.

Raw ``requests`` against Select Star's REST API v1
(``https://api.production.selectstar.com``), no vendor SDK. Auth is a static
API token issued out-of-band in the Select Star console, header shape
``Authorization: Token <token>`` (note: Select Star's own ``Token`` scheme,
not ``Bearer`` — distinct from the AppOmni/Snyk/UpGuard "just set the header"
collectors, which all use ``Bearer``).

Pagination is DRF-style (``{"count", "next", "previous", "results"}``) with
``next`` already a complete, pre-parameterised URL — the same shape as
AppOmni's ``policies``/``open_policy_issues`` and Kandji's
``blueprints``/``vulnerabilities``: the first page is built from a base
``page_size`` param, every subsequent page just ``GET``s the given ``next``
URL directly.

``endpoint`` is optional config (defaults to Select Star's production SaaS
host); overridable for a differently-hosted tenant, same shape as DNSimple's
``endpoint``.

Resources: ``databases``, ``tables`` — Select Star's core data-catalog
inventory (data source connections and the tables/views within them).
Lineage, column-level metadata, and usage-analytics endpoints are out of
scope for this initial cut.

**Caveat:** this was ported from a legacy in-house extraction script (which
called only ``/v1/databases/`` and ``/v1/tables/``) and cross-checked against
Select Star's public API documentation, not a live schema introspection
against a real workspace — same caveat tier as ``wiz.py``, ``appomni.py``,
``snyk.py``, and others. No live credentials were available to verify this
collector. Verify field names/nesting against a real workspace's response
before relying on this collector.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger = logging.getLogger("posture.collectors.select_star")

_DEFAULT_ENDPOINT = "https://api.production.selectstar.com"
_DATABASES_PATH = "/v1/databases/"
_TABLES_PATH = "/v1/tables/"
_PAGE_SIZE = 100

MANIFEST: dict[str, dict[str, Any]] = {
    "databases": {
        "endpoint": _DATABASES_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "native_type": ("native_type", "str"),
            "description": ("description", "str"),
            "url": ("url", "str"),
            "table_count": ("table_count", "int"),
            "tags": ("tags", "json"),
            "owners": ("owners", "json"),
            "created_at": ("created_at", "datetime"),
            "updated_at": ("updated_at", "datetime"),
        },
    },
    "tables": {
        "endpoint": _TABLES_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "full_name": ("full_name", "str"),
            "database_id": ("database.id", "str"),
            "database_name": ("database.name", "str"),
            "schema_name": ("schema_name", "str"),
            "table_type": ("table_type", "str"),
            "description": ("description", "str"),
            "url": ("url", "str"),
            "row_count": ("row_count", "int"),
            "column_count": ("column_count", "int"),
            "tags": ("tags", "json"),
            "owners": ("owners", "json"),
            "popularity": ("popularity", "float"),
            "last_refreshed_at": ("last_refreshed_at", "datetime"),
            "created_at": ("created_at", "datetime"),
            "updated_at": ("updated_at", "datetime"),
        },
    },
}

_RESOURCE_PATHS: dict[str, str] = {
    "databases": _DATABASES_PATH,
    "tables": _TABLES_PATH,
}


class SelectStarCollector(Collector):
    env_prefix = "SELECTSTAR"
    display_name = "Select Star"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {"token": True, "endpoint": False}
    url_config_keys: tuple[str, ...] = ("endpoint",)

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        self._base_url = self._config.get("endpoint", _DEFAULT_ENDPOINT)

    def _authenticate(self) -> None:
        self._session.headers["Authorization"] = f"Token {self._config['token']}"
        self._session.headers["Accept"] = "application/json"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource in _RESOURCE_PATHS:
            return self._fetch_list_page(_RESOURCE_PATHS[resource], kwargs, cursor)
        raise ValueError(f"Unsupported resource '{resource}'")

    def _fetch_list_page(
        self, path: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is None:
            params: dict[str, Any] = {"page_size": _PAGE_SIZE}
            params.update(kwargs)
            body = self._get(self._base_url + path, params=params).json()
        else:
            body = self._get(cursor).json()  # cursor is already a full URL
        return body.get("results", []) or [], body.get("next") or None

    def _get(self, url: str, params: dict[str, Any] | None = None) -> Any:
        response = self._session.get(url, params=params, timeout=60)
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitedSignal(
                retry_after=float(retry_after) if retry_after else None
            )
        if response.status_code in (401, 403):
            raise UnauthorizedSignal()
        response.raise_for_status()
        return response
