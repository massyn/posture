"""runZero collector.

Raw ``requests`` against runZero's Export API
(``https://console.runzero.com/api/v1.0``), no vendor SDK. Auth is a static
API token issued out-of-band in the runZero console (an "Export API Key",
scoped read-only by design — runZero's export tokens carry no write
capability), same "just set the header" shape as AppOmni/Snyk/UpGuard
(``Authorization: Bearer <token>``).

``assets`` hits the bulk asset-inventory export (``/export/org/assets.json``)
— a single unpaginated request returning a bare JSON array of every asset in
the org the token is scoped to, the same "no envelope at all" shape as
Kandji's ``devices``/AppOmni's ``monitored_services``. runZero's export
endpoint accepts an optional ``search`` query (RZQL syntax) to filter the
result server-side; passed through via kwargs, merged onto no default filter
(bare ``collect("assets")`` returns everything).

``endpoint`` is optional config (defaults to runZero's SaaS console); a
self-hosted/on-prem console reachable at a different host overrides it, same
"operator-suppliable, normalized host" shape as DNSimple's ``endpoint``.

Resources: ``assets``.

**Caveat:** this was ported from a legacy in-house extraction script (which
called only ``/export/org/assets.json``) and cross-checked against runZero's
public Export API documentation, not a live schema introspection against a
real console — same caveat tier as ``wiz.py``, ``appomni.py``, ``snyk.py``,
and others. No live credentials were available to verify this collector.
Verify field names/nesting against a real org's response before relying on
this collector.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger = logging.getLogger("posture.collectors.runzero")

_DEFAULT_ENDPOINT = "https://console.runzero.com/api/v1.0"
_ASSETS_PATH = "/export/org/assets.json"

MANIFEST: dict[str, dict[str, Any]] = {
    "assets": {
        "endpoint": _ASSETS_PATH,
        "columns": {
            "id": ("id", "str"),
            "org_id": ("org_id", "str"),
            "site_id": ("site_id", "str"),
            "site_name": ("site_name", "str"),
            "name": ("name", "str"),
            "first_seen": ("first_seen", "datetime"),
            "last_seen": ("last_seen", "datetime"),
            "alive": ("alive", "bool"),
            "addresses": ("addresses", "json"),
            "addresses_extra": ("addresses_extra", "json"),
            "mac_addresses": ("mac_addresses", "json"),
            "mac_vendors": ("mac_vendors", "json"),
            "hostnames": ("names", "json"),
            "domains": ("domains", "json"),
            "hw": ("hw", "str"),
            "hw_vendor": ("hw_vendor", "str"),
            "hw_product": ("hw_product", "str"),
            "hw_types": ("hw_types", "json"),
            "os": ("os", "str"),
            "os_version": ("os_version", "str"),
            "os_vendor": ("os_vendor", "str"),
            "type": ("type", "str"),
            "subtype": ("subtype", "str"),
            "sources": ("sources", "json"),
            "tags": ("tags", "json"),
            "comments": ("comments", "str"),
            "detected_by": ("detected_by", "str"),
            "created_at": ("created_at", "datetime"),
            "updated_at": ("updated_at", "datetime"),
        },
    },
}


class RunzeroCollector(Collector):
    env_prefix = "RUNZERO"
    display_name = "runZero"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {"token": True, "endpoint": False}
    url_config_keys: tuple[str, ...] = ("endpoint",)

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        self._base_url = self._config.get("endpoint", _DEFAULT_ENDPOINT)

    def _authenticate(self) -> None:
        self._session.headers["Authorization"] = f"Bearer {self._config['token']}"
        self._session.headers["Accept"] = "application/json"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "assets":
            return self._fetch_assets_page(kwargs, cursor)
        raise ValueError(f"Unsupported resource '{resource}'")

    def _fetch_assets_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # export endpoint returns everything in one call

        response = self._get(self._base_url + _ASSETS_PATH, params=kwargs)
        records = response.json()
        return records or [], None

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
