"""Kandji collector.

Apple-only MDM (macOS/iOS/iPadOS/tvOS) — Kandji has rebranded to "Iru", but
existing tenant hosts still resolve at ``https://<subdomain>.api.kandji.io``
(or ``.api.eu.kandji.io`` for EU tenants), so ``api_url`` is required config
(the full tenant host, no cross-tenant discovery mechanism exists) rather
than a bare subdomain — same "no discovery, operator supplies the host"
shape as ``wiz.py``'s ``api_endpoint``.

Auth is a static bearer token issued out-of-band in the Kandji console (no
OAuth flow) — same "just set the header" shape as AppOmni/Snyk/UpGuard.

Raw ``requests`` against the REST API — no vendor SDK. Two pagination
shapes coexist on this API:

- ``devices``: bare JSON list, no envelope at all — the same shape as
  AppOmni's ``monitored_services``. Paginated with ``limit``/``offset``;
  stops once a page returns fewer than ``limit`` records (Kandji's own
  default page cap is 300).
- ``blueprints`` and ``vulnerabilities``: a DRF-style envelope
  (``{"count", "next", "previous", "results"}``) where ``next`` is already
  a complete, pre-parameterised URL — the same cursor shape as AppOmni's
  ``policies``/``open_policy_issues``, just with different default query
  param names per resource (``vulnerabilities`` uses ``page``/``size``
  rather than ``limit``/``offset``, per Kandji's own docs — irrelevant
  once ``next`` is doing the driving).

Resources: ``devices``, ``device_details`` (per-device fan-out, requires
``devices`` ids), ``blueprints``, ``vulnerabilities``.

**Caveat — not live-verified:** ``MANIFEST`` column paths were built from
Kandji's public API reference, a third-party Python wrapper
(frefrik/python-kandji), and a third-party MCP server built against this
API, not a live schema introspection against a real tenant — same caveat
tier as ``wiz.py``, ``appomni.py``, ``snyk.py``, ``cloudflare.py``,
``dnsimple.py``, ``phriendly_phishing.py``, ``vanta.py``, and
``crowdstrike_identity.py``. ``device_details``'s security-posture field
nesting (FileVault/firewall/Gatekeeper/SIP) in particular is a best-effort
guess at naming conventions Kandji uses elsewhere in its product, not a
confirmed response shape — verify against a real tenant's response before
relying on this collector. ``vulnerabilities``' exact grain (a CVE catalog
vs. a per-device detection feed) is also unconfirmed; the endpoint path
itself (``/api/v1/vulnerability-management/vulnerabilities``) was
independently confirmed via Kandji's own docs and the third-party MCP
server, but which grain it returns was not.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger = logging.getLogger("posture.collectors.kandji")

_DEVICES_PATH = "/api/v1/devices"
_DEVICE_DETAILS_PATH = "/api/v1/devices/{id}/details"
_BLUEPRINTS_PATH = "/api/v1/blueprints"
_VULNERABILITIES_PATH = "/api/v1/vulnerability-management/vulnerabilities"

_DEVICES_PAGE_SIZE = 300
_VULNERABILITIES_PAGE_SIZE = 300

_DEVICE_DETAILS_MAX_WORKERS = 10

MANIFEST: dict[str, dict[str, Any]] = {
    "devices": {
        "endpoint": _DEVICES_PATH,
        "columns": {
            "device_id": ("device_id", "str"),
            "device_name": ("device_name", "str"),
            "model": ("model", "str"),
            "platform": ("platform", "str"),
            "os_version": ("os_version", "str"),
            "serial_number": ("serial_number", "str"),
            "asset_tag": ("asset_tag", "str"),
            "blueprint_id": ("blueprint_id", "str"),
            "mdm_enabled": ("mdm_enabled", "bool"),
            "agent_installed": ("agent_installed", "bool"),
            "agent_version": ("agent_version", "str"),
            "is_missing": ("is_missing", "bool"),
            "is_removed": ("is_removed", "bool"),
            "first_enrollment": ("first_enrollment", "datetime"),
            "last_enrollment": ("last_enrollment", "datetime"),
            "last_check_in": ("last_check_in", "datetime"),
            "user_email": ("user.email", "str"),
        },
    },
    "device_details": {
        # Not derived_from "devices": each device's detail is its own
        # network call by id, not data nested inside the device list
        # record — the same shape as jamf.py's computers_inventory_detail.
        "endpoint": _DEVICE_DETAILS_PATH,
        "columns": {
            "device_id": ("device_id", "str"),
            "device_name": ("device_name", "str"),
            "serial_number": ("serial_number", "str"),
            "platform": ("platform", "str"),
            "os_version": ("os_version", "str"),
            "last_check_in": ("last_check_in", "datetime"),
            "is_supervised": ("is_supervised", "bool"),
            "filevault_enabled": ("security.filevault.enabled", "bool"),
            "filevault_recovery_key_escrowed": (
                "security.filevault.recovery_key_escrowed",
                "bool",
            ),
            "firewall_enabled": ("security.firewall.enabled", "bool"),
            "gatekeeper_enabled": ("security.gatekeeper.enabled", "bool"),
            "sip_enabled": (
                "security.system_integrity_protection.enabled",
                "bool",
            ),
        },
    },
    "blueprints": {
        "endpoint": _BLUEPRINTS_PATH,
        "columns": {
            "blueprint_id": ("id", "str"),
            "name": ("name", "str"),
        },
    },
    "vulnerabilities": {
        "endpoint": _VULNERABILITIES_PATH,
        "columns": {
            "vulnerability_id": ("id", "str"),
            "cve_id": ("cve_id", "str"),
            "device_id": ("device_id", "str"),
            "severity": ("severity", "str"),
            "cvss_score": ("cvss_score", "float"),
            "status": ("status", "str"),
            "description": ("description", "str"),
            "published_date": ("published_date", "datetime"),
            "detected_date": ("detected_date", "datetime"),
        },
    },
}


class KandjiCollector(Collector):
    env_prefix = "KANDJI"
    display_name = "Kandji"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {"api_url": True, "api_token": True}
    url_config_keys = ("api_url",)

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        self._base_url = self._config["api_url"]

    def _authenticate(self) -> None:
        self._session.headers["Accept"] = "application/json"
        self._session.headers["Authorization"] = f"Bearer {self._config['api_token']}"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "device_details":
            return self._fetch_device_details_page(kwargs, cursor)
        if resource == "devices":
            return self._fetch_devices_page(kwargs, cursor)
        return self._fetch_drf_page(resource, kwargs, cursor)

    def _fetch_devices_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        offset = cursor if cursor is not None else 0
        params: dict[str, Any] = {"limit": _DEVICES_PAGE_SIZE, "offset": offset}
        params.update(kwargs)

        response = self._get(self._base_url + _DEVICES_PATH, params=params)
        records = response.json()
        if not records:
            return [], None

        next_cursor = offset + len(records) if len(records) == params["limit"] else None
        return records, next_cursor

    def _fetch_drf_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            # "next" is already a complete, pre-parameterised URL.
            response = self._get(cursor)
        else:
            endpoint = self.manifest[resource]["endpoint"]
            params: dict[str, Any] = (
                {"page": 1, "size": _VULNERABILITIES_PAGE_SIZE}
                if resource == "vulnerabilities"
                else {}
            )
            params.update(kwargs)
            response = self._get(self._base_url + endpoint, params=params)

        payload = response.json()
        records = payload.get("results", []) or []
        next_cursor = payload.get("next")
        return records, next_cursor

    def _fetch_device_details_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # entire fan-out already completed on first call

        device_ids = kwargs.get("device_ids")
        if device_ids is None:
            device_ids = self._all_device_ids()
        if not device_ids:
            return [], None

        max_workers = kwargs.get("max_workers", _DEVICE_DETAILS_MAX_WORKERS)
        workers = max(1, min(max_workers, len(device_ids)))

        records = self._resumable_fanout(
            "device_details", device_ids, self._fetch_device_detail, workers
        )
        return records, None

    def _fetch_device_detail(self, device_id: Any) -> dict[str, Any]:
        url = self._base_url + _DEVICE_DETAILS_PATH.format(id=device_id)
        return self._get(url).json()

    def _all_device_ids(self) -> list[str]:
        raw_devices = self._get_raw("devices", {})
        return [
            str(device["device_id"])
            for device in raw_devices
            if device.get("device_id") is not None
        ]

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
                extra={"source": "kandji", "status_code": response.status_code},
            )
        response.raise_for_status()
        return response
