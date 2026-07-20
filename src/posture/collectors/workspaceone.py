"""Workspace ONE (VMware UEM) collector.

Raw ``requests`` against the standard Workspace ONE UEM REST API — no vendor
SDK. Auth, retry, pagination, caching, and reporting all come from the base
Collector; this module only knows Workspace ONE's endpoints and resource
manifests.

Resources: ``computers``.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal
from posture.exceptions import AuthenticationError

logger = logging.getLogger("posture.collectors.workspaceone")

_DEVICES_SEARCH_PATH = "/API/mdm/devices/search"
_PAGE_SIZE = 500

# Matches the accelerator's default. Region-specific (na/emea/apac) with no
# documented way to derive it from api_server — if your tenant isn't APAC,
# set WORKSPACEONE_TOKEN_URL explicitly.
_DEFAULT_TOKEN_URL = "https://apac.uemauth.workspaceone.com/connect/token"

MANIFEST: dict[str, dict[str, Any]] = {
    "computers": {
        "endpoint": _DEVICES_SEARCH_PATH,
        "columns": {
            # ip_address is deliberately omitted: the reference implementation
            # picks the first non-null ip across a list of network-info
            # entries — a computed fallback, not a raw allowlisted field.
            "device_id": ("Id.Value", "str"),
            "uuid": ("Uuid", "str"),
            "udid": ("udid", "str"),
            "serial_number": ("serial_number", "str"),
            "mac_address": ("mac_address", "str"),
            "imei": ("imei", "str"),
            "asset_number": ("asset_number", "str"),
            "device_friendly_name": ("device_friendly_name", "str"),
            "device_reported_name": ("device_reported_name", "str"),
            "platform_name": ("platform_name", "str"),
            "device_type": ("device_type", "str"),
            "model_identifier": ("model_identifier", "str"),
            "model": ("model", "str"),
            "operating_system": ("operating_system", "str"),
            "os_build_version": ("os_build_version", "str"),
            "last_seen": ("last_seen", "datetime"),
            "last_enrolled_on": ("last_enrolled_on", "str"),
            "enrollment_status": ("enrollment_status", "str"),
            "compliance_status": ("compliance_status", "str"),
            "compromised_status": ("compromised_status", "str"),
            "is_supervised": ("is_supervised", "bool"),
            "ownership": ("ownership", "str"),
            "organization_group_name": ("organization_group_name", "str"),
            "organization_group_uuid": ("organization_group_uuid", "str"),
            "enrollment_user_name": ("enrollment_user_name", "str"),
            "enrollment_user_uuid": ("enrollment_user_uuid", "str"),
            "enrollment_user_email": ("enrollment_user_email_address", "str"),
            "managed_by": ("managed_by", "str"),
            "time_zone": ("time_zone", "str"),
        },
    },
}


class WorkspaceOneCollector(Collector):
    env_prefix = "WORKSPACEONE"
    manifest = MANIFEST
    # token_url is deliberately not a required key: it's resolved with a
    # default below (accelerator parity), not fail-fast like the rest.
    required_config_keys = ("client_id", "client_secret", "api_server")

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._base_url = ""
        self._token_url = (
            (config or {}).get("token_url")
            or os.environ.get("WORKSPACEONE_TOKEN_URL")
            or _DEFAULT_TOKEN_URL
        )

    def _authenticate(self) -> None:
        response = self._session.post(
            self._token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self._config["client_id"],
                "client_secret": self._config["client_secret"],
            },
            timeout=30,
        )
        if response.status_code == 401:
            raise AuthenticationError(
                "Workspace ONE rejected client credentials",
                source="workspaceone",
                hint="check WORKSPACEONE_CLIENT_ID / WORKSPACEONE_CLIENT_SECRET",
            )
        if response.status_code != 200:
            logger.warning(
                "unexpected status code",
                extra={"source": "workspaceone", "status_code": response.status_code},
            )
        response.raise_for_status()

        token = response.json()["access_token"]
        self._session.headers["Authorization"] = f"Bearer {token}"
        self._session.headers["Accept"] = "application/json;version=3"
        self._session.headers["Content-Type"] = "application/json"

        self._base_url = f"https://{self._config['api_server']}"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource != "computers":
            raise ValueError(f"Unsupported resource '{resource}'")

        page = cursor if cursor is not None else 0
        params: dict[str, Any] = {"pagesize": _PAGE_SIZE, "page": page}
        params.update(kwargs)

        response = self._session.get(
            self._base_url + _DEVICES_SEARCH_PATH, params=params, timeout=60
        )
        self._raise_for_transient_errors(response)
        body = response.json()

        devices = body.get("devices", [])
        if not devices:
            return [], None

        total = body.get("total", 0)
        fetched_through = (page * _PAGE_SIZE) + len(devices)
        next_cursor = page + 1 if fetched_through < total else None
        return devices, next_cursor

    @staticmethod
    def _raise_for_transient_errors(response: Any) -> None:
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitedSignal(
                retry_after=float(retry_after) if retry_after else None
            )
        if response.status_code == 401:
            raise UnauthorizedSignal()
        if response.status_code != 200:
            logger.warning(
                "unexpected status code",
                extra={"source": "workspaceone", "status_code": response.status_code},
            )
        response.raise_for_status()
