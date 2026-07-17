"""Jamf Pro collector.

Raw ``requests`` against the Jamf Pro API — no vendor SDK. Auth, retry,
pagination, caching, and reporting all come from the base Collector; this
module only knows Jamf's endpoints and resource manifests.

Schema note: the reference implementation only declares renames for a
handful of fields per table and passes the rest of each response through via
generic flattening (``pd.json_normalize``). posture's manifest is
allowlist-only — no generic flattening — so only the explicitly named fields
below are ported. This is narrower than what the accelerator actually
captures in production; it is not a guess at the missing fields.

Resources: ``computers_inventory``, ``computers_inventory_detail`` (requires
``computers_inventory`` ids), ``mobile_devices``, ``policies``, ``categories``,
``buildings``, ``departments``.
"""

from __future__ import annotations

from typing import Any

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal
from posture.exceptions import AuthenticationError

_PAGE_SIZE = 100

_ENDPOINTS = {
    "computers_inventory": "/api/v2/computers-inventory",
    "computers_inventory_detail": "/api/v2/computers-inventory-detail/{id}",
    "mobile_devices": "/api/v2/mobile-devices",
    "policies": "/api/v1/policies",
    "categories": "/api/v1/categories",
    "buildings": "/api/v1/buildings",
    "departments": "/api/v1/departments",
}

MANIFEST: dict[str, dict[str, Any]] = {
    "computers_inventory": {
        "endpoint": _ENDPOINTS["computers_inventory"],
        "columns": {
            "computer_id": ("id", "str"),
            "device_udid": ("udid", "str"),
            "serial_number": ("serialNumber", "str"),
            "last_inventory_update_timestamp": (
                "lastInventoryUpdateTimestamp",
                "datetime",
            ),
            "os_version": ("operatingSystem.version", "str"),
        },
    },
    "computers_inventory_detail": {
        # Not derived_from "computers_inventory": each computer's detail is
        # its own network call by id, not data nested inside the inventory
        # list record.
        "endpoint": _ENDPOINTS["computers_inventory_detail"],
        "columns": {
            "computer_inventory_detail_id": ("id", "str"),
            "serial_number": ("serialNumber", "str"),
            "device_udid": ("udid", "str"),
        },
    },
    "mobile_devices": {
        "endpoint": _ENDPOINTS["mobile_devices"],
        "columns": {
            "mobile_device_id": ("id", "str"),
            "device_udid": ("udid", "str"),
            "serial_number": ("serialNumber", "str"),
            "last_inventory_update_timestamp": (
                "lastInventoryUpdateTimestamp",
                "datetime",
            ),
            "os_version": ("osVersion", "str"),
        },
    },
    "policies": {
        "endpoint": _ENDPOINTS["policies"],
        "columns": {
            "policy_id": ("id", "str"),
            "policy_name": ("name", "str"),
            "is_enabled": ("enabled", "bool"),
        },
    },
    "categories": {
        "endpoint": _ENDPOINTS["categories"],
        "columns": {
            "category_id": ("id", "str"),
            "category_name": ("name", "str"),
        },
    },
    "buildings": {
        "endpoint": _ENDPOINTS["buildings"],
        "columns": {
            "building_id": ("id", "str"),
            "building_name": ("name", "str"),
        },
    },
    "departments": {
        "endpoint": _ENDPOINTS["departments"],
        "columns": {
            "department_id": ("id", "str"),
            "department_name": ("name", "str"),
        },
    },
}


class JamfCollector(Collector):
    env_prefix = "JAMF"
    manifest = MANIFEST
    required_config_keys = ("url", "client_id", "client_secret")

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._base_url = self._config["url"].rstrip("/")

    def _authenticate(self) -> None:
        response = self._session.post(
            f"{self._base_url}/api/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self._config["client_id"],
                "client_secret": self._config["client_secret"],
            },
            timeout=30,
        )
        if response.status_code == 401:
            raise AuthenticationError(
                "Jamf rejected client credentials",
                source="jamf",
                hint="check JAMF_CLIENT_ID / JAMF_CLIENT_SECRET",
            )
        response.raise_for_status()

        token = response.json()["access_token"]
        self._session.headers["Authorization"] = f"Bearer {token}"
        self._session.headers["Accept"] = "application/json"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "computers_inventory_detail":
            return self._fetch_computer_detail_page(kwargs, cursor)
        return self._fetch_list_page(resource, kwargs, cursor)

    def _fetch_list_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        endpoint = _ENDPOINTS[resource]
        page = cursor if cursor is not None else 0
        params: dict[str, Any] = {"page": page, "page-size": _PAGE_SIZE}
        params.update(kwargs)

        response = self._get(self._base_url + endpoint, params=params)
        records = response.json().get("results", [])
        if not records:
            return [], None

        next_cursor = page + 1 if len(records) == _PAGE_SIZE else None
        return records, next_cursor

    def _fetch_computer_detail_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # all ids already fetched on the first call

        computer_ids = kwargs.get("computer_ids")
        if computer_ids is None:
            computer_ids = self._all_computer_ids()
        if not computer_ids:
            return [], None

        detail_path = _ENDPOINTS["computers_inventory_detail"]
        records: list[dict[str, Any]] = []
        for computer_id in computer_ids:
            url = self._base_url + detail_path.format(id=computer_id)
            response = self._get(url)
            records.append(response.json())

        return records, None

    def _all_computer_ids(self) -> list[str]:
        raw_computers = self._get_raw("computers_inventory", {})
        return [
            str(computer["id"])
            for computer in raw_computers
            if computer.get("id") is not None
        ]

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
