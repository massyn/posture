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

Resources: ``devices``, ``device_details`` (per-device ``GET
/devices/{id}/details`` fan-out), ``device_parameters`` (per-device ``GET
/devices/{id}/parameters`` fan-out, one row per blueprint compliance
parameter), ``device_library_items`` (per-device ``GET
/devices/{id}/status`` fan-out, one row per assigned library item),
``blueprints``, ``vulnerabilities``. The three fan-out resources each
declare ``requires: "devices"`` so the device id list is served from the
on-disk session cache rather than re-collected over the network per
resource — the same per-item fan-out shape as ``intune.py``'s
``managed_device_detail``.

``devices``, ``device_details``, ``device_parameters`` and
``device_library_items`` column paths were verified against a live tenant's
responses. ``device_details`` in particular is a deeply section-keyed
object (``general``, ``mdm``, ``filevault``, ``hardware_overview``,
``activation_lock``, ``recovery_information``, ``security_information``,
``kandji_agent``, ``network``) — firewall/Gatekeeper/SIP state is *not*
carried there; it surfaces only as named compliance rows in
``device_parameters`` (``name`` = "Enable Firewall" / "Enable Gatekeeper" /
"Enable System Integrity Protection"), and only when the tenant's blueprint
includes those checks.

**Caveat — not live-verified:** ``blueprints`` and ``vulnerabilities``
column paths were built from Kandji's public API reference, a third-party
Python wrapper (frefrik/python-kandji), and a third-party MCP server built
against this API, not a live schema introspection — same caveat tier as
``wiz.py``, ``appomni.py``, ``snyk.py``, ``cloudflare.py``, ``dnsimple.py``,
``phriendly_phishing.py``, ``vanta.py``, and ``crowdstrike_identity.py``.
``vulnerabilities``' exact grain (a CVE catalog vs. a per-device detection
feed) is also unconfirmed; the endpoint path itself
(``/api/v1/vulnerability-management/vulnerabilities``) was independently
confirmed via Kandji's own docs and the third-party MCP server, but which
grain it returns was not.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger = logging.getLogger("posture.collectors.kandji")

_DEVICES_PATH = "/api/v1/devices"
_BLUEPRINTS_PATH = "/api/v1/blueprints"
_VULNERABILITIES_PATH = "/api/v1/vulnerability-management/vulnerabilities"

# Per-device fan-out resources: resource -> (path template, key of the list
# to explode within the per-device response). A None list key means the
# response body is itself the single record for that device.
_FANOUT_SPECS: dict[str, tuple[str, str | None]] = {
    "device_details": ("/api/v1/devices/{id}/details", None),
    "device_parameters": ("/api/v1/devices/{id}/parameters", "parameters"),
    "device_library_items": ("/api/v1/devices/{id}/status", "library_items"),
}

_DEVICES_PAGE_SIZE = 300
_VULNERABILITIES_PAGE_SIZE = 300

_DEVICE_FANOUT_MAX_WORKERS = 10

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
            "udid": ("udid", "str"),
            "asset_tag": ("asset_tag", "str"),
            "blueprint_id": ("blueprint_id", "str"),
            "blueprint_name": ("blueprint_name", "str"),
            "mdm_enabled": ("mdm_enabled", "bool"),
            "agent_installed": ("agent_installed", "bool"),
            "agent_version": ("agent_version", "str"),
            "is_missing": ("is_missing", "bool"),
            "is_removed": ("is_removed", "bool"),
            "lost_mode_status": ("lost_mode_status", "str"),
            "first_enrollment": ("first_enrollment", "datetime"),
            "last_enrollment": ("last_enrollment", "datetime"),
            "last_check_in": ("last_check_in", "datetime"),
            "user_email": ("user.email", "str"),
            "user_name": ("user.name", "str"),
            "user_id": ("user.id", "str"),
            "tags": ("tags", "json"),
        },
    },
    "device_details": {
        # Not derived_from "devices": each device's detail is its own network
        # call by id, not data nested inside the device list record — the
        # same shape as jamf.py's computers_inventory_detail. requires
        # "devices" so the id list replays from the session cache.
        "endpoint": _FANOUT_SPECS["device_details"][0],
        "requires": "devices",
        "columns": {
            "device_id": ("general.device_id", "str"),
            "device_name": ("general.device_name", "str"),
            "platform": ("general.platform", "str"),
            "os_version": ("general.os_version", "str"),
            "system_version": ("general.system_version", "str"),
            "model": ("general.model", "str"),
            "serial_number": ("hardware_overview.serial_number", "str"),
            "udid": ("hardware_overview.udid", "str"),
            "processor_name": ("hardware_overview.processor_name", "str"),
            "memory": ("hardware_overview.memory", "str"),
            "assigned_user_email": ("general.assigned_user.email", "str"),
            "assigned_user_name": ("general.assigned_user.name", "str"),
            "blueprint_name": ("general.blueprint_name", "str"),
            "blueprint_uuid": ("general.blueprint_uuid", "str"),
            "last_user": ("general.last_user", "str"),
            "first_enrollment": ("general.first_enrollment", "datetime"),
            "last_enrollment": ("general.last_enrollment", "datetime"),
            "mdm_enabled": ("mdm.mdm_enabled", "bool"),
            "is_supervised": ("mdm.supervised", "bool"),
            "mdm_install_date": ("mdm.install_date", "datetime"),
            "last_check_in": ("mdm.last_check_in", "datetime"),
            "agent_installed": ("kandji_agent.agent_installed", "bool"),
            "agent_version": ("kandji_agent.agent_version", "str"),
            "agent_last_check_in": ("kandji_agent.last_check_in", "datetime"),
            "filevault_enabled": ("filevault.filevault_enabled", "bool"),
            "filevault_recovery_key_type": (
                "filevault.filevault_recoverykey_type",
                "str",
            ),
            "filevault_recovery_key_escrowed": (
                "filevault.filevault_prk_escrowed",
                "bool",
            ),
            "filevault_next_rotation": (
                "filevault.filevault_next_rotation",
                "datetime",
            ),
            "filevault_regen_required": (
                "filevault.filevault_regen_required",
                "bool",
            ),
            "activation_lock_enabled": (
                "activation_lock.device_activation_lock_enabled",
                "bool",
            ),
            "user_activation_lock_enabled": (
                "activation_lock.user_activation_lock_enabled",
                "bool",
            ),
            "activation_lock_supported": (
                "activation_lock.activation_lock_supported",
                "bool",
            ),
            "recovery_lock_enabled": (
                "recovery_information.recovery_lock_enabled",
                "bool",
            ),
            "firmware_password_exists": (
                "recovery_information.firmware_password_exist",
                "bool",
            ),
            "remote_desktop_enabled": (
                "security_information.remote_desktop_enabled",
                "bool",
            ),
            "auto_enrolled": (
                "automated_device_enrollment.auto_enrolled",
                "bool",
            ),
            "local_hostname": ("network.local_hostname", "str"),
            "mac_address": ("network.mac_address", "str"),
            "ip_address": ("network.ip_address", "str"),
            "public_ip": ("network.public_ip", "str"),
        },
    },
    "device_parameters": {
        # Per-device GET /devices/{id}/parameters fan-out. Grain: one row per
        # device per blueprint compliance parameter. device_id is injected
        # client-side from the fan-out id (see _fetch_one_subresource).
        "endpoint": _FANOUT_SPECS["device_parameters"][0],
        "requires": "devices",
        "columns": {
            "device_id": ("device_id", "str"),
            "item_id": ("item_id", "str"),
            "name": ("name", "str"),
            "category": ("category", "str"),
            "subcategory": ("subcategory", "str"),
            "status": ("status", "str"),
        },
    },
    "device_library_items": {
        # Per-device GET /devices/{id}/status fan-out. Grain: one row per
        # device per assigned library item (profiles, custom apps/scripts,
        # OS releases). device_id is injected client-side from the fan-out
        # id. The verbose free-text last_audit_log / log fields are
        # deliberately not carried — allowlist, not a flattener.
        "endpoint": _FANOUT_SPECS["device_library_items"][0],
        "requires": "devices",
        "columns": {
            "device_id": ("device_id", "str"),
            "library_item_row_id": ("id", "str"),
            "item_id": ("item_id", "str"),
            "name": ("name", "str"),
            "type": ("type", "str"),
            "status": ("status", "str"),
            "rules_present": ("rules_present", "bool"),
            "reported_at": ("reported_at", "datetime"),
            "most_recent_action": ("most_recent_action", "datetime"),
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
        if resource in _FANOUT_SPECS:
            return self._fetch_fanout_page(resource, kwargs, cursor)
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

    def _fetch_fanout_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # entire fan-out already completed on first call

        device_ids = kwargs.get("device_ids")
        if device_ids is None:
            device_ids = self._all_device_ids()
        if not device_ids:
            return [], None

        max_workers = kwargs.get("max_workers", _DEVICE_FANOUT_MAX_WORKERS)
        workers = max(1, min(max_workers, len(device_ids)))

        records = self._resumable_fanout(
            resource,
            device_ids,
            lambda device_id: self._fetch_one_subresource(resource, device_id),
            workers,
        )
        return records, None

    def _fetch_one_subresource(self, resource: str, device_id: Any) -> Any:
        path, list_key = _FANOUT_SPECS[resource]
        payload = self._get(self._base_url + path.format(id=device_id)).json()
        if list_key is None:
            return payload
        items = payload.get(list_key) or []
        return [{**item, "device_id": str(device_id)} for item in items]

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
