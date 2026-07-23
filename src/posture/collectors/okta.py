"""Okta collector.

Raw ``requests`` against the standard Okta REST API — no Okta SDK (its API
is generic REST with Link-header pagination; nothing here needs vendor
machinery the base class can't already generalise). Auth, retry, pagination,
caching, and reporting all come from the base Collector; this module only
knows Okta's endpoints and resource manifests.

Resources: ``users``, ``devices``, ``device_users``. Audit ``logs`` were
deliberately left out of scope.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger = logging.getLogger("posture.collectors.okta")

_USERS_PATH = "/api/v1/users"
_DEVICES_PATH = "/api/v1/devices"
_DEVICE_USERS_PATH = "/api/v1/devices/{device_id}/users"

_PAGE_LIMIT = 200
_LINK_NEXT_RE = re.compile(r'<([^>]+)>;\s*rel="next"')

MANIFEST: dict[str, dict[str, Any]] = {
    "users": {
        "endpoint": _USERS_PATH,
        "columns": {
            "id": ("id", "str"),
            "status": ("status", "str"),
            "created": ("created", "datetime"),
            "activated": ("activated", "datetime"),
            "status_changed": ("statusChanged", "datetime"),
            "last_login": ("lastLogin", "datetime"),
            "last_updated": ("lastUpdated", "datetime"),
            "password_changed": ("passwordChanged", "datetime"),
            "type_id": ("type.id", "str"),
            "profile_login": ("profile.login", "str"),
            "profile_first_name": ("profile.firstName", "str"),
            "profile_last_name": ("profile.lastName", "str"),
            "profile_nick_name": ("profile.nickName", "str"),
            "profile_display_name": ("profile.displayName", "str"),
            "profile_email": ("profile.email", "str"),
            "profile_secondEmail": ("profile.secondEmail", "str"),
            "profile_url": ("profile.profileUrl", "str"),
            "profile_preferred_language": ("profile.preferredLanguage", "str"),
            "profile_user_type": ("profile.userType", "str"),
            "profile_organization": ("profile.organization", "str"),
            "profile_title": ("profile.title", "str"),
            "profile_division": ("profile.division", "str"),
            "profile_department": ("profile.department", "str"),
            "profile_cost_center": ("profile.costCenter", "str"),
            "profile_employee_number": ("profile.employeeNumber", "str"),
            "profile_mobile_phone": ("profile.mobilePhone", "str"),
            "profile_primary_phone": ("profile.primaryPhone", "str"),
            "profile_street_address": ("profile.streetAddress", "str"),
            "profile_city": ("profile.city", "str"),
            "profile_state": ("profile.state", "str"),
            "profile_zip_code": ("profile.zipCode", "str"),
            "profile_country_code": ("profile.countryCode", "str"),
        },
    },
    "devices": {
        "endpoint": _DEVICES_PATH,
        "columns": {
            "id": ("id", "str"),
            "created": ("created", "datetime"),
            "status": ("status", "str"),
            "lastupdated": ("lastUpdated", "datetime"),
            "profile_displayname": ("profile.displayName", "str"),
            "profile_platform": ("profile.platform", "str"),
            "profile_manufacturer": ("profile.manufacturer", "str"),
            "profile_model": ("profile.model", "str"),
            "profile_osversion": ("profile.osVersion", "str"),
            "profile_registered": ("profile.registered", "bool"),
            "profile_securehardwarepresent": ("profile.secureHardwarePresent", "bool"),
            "profile_authenticatorappkey": ("profile.authenticatorAppKey", "str"),
            "profile_serialnumber": ("profile.serialNumber", "str"),
            "profile_udid": ("profile.udid", "str"),
            "profile_imei": ("profile.imei", "str"),
            "profile_meid": ("profile.meid", "str"),
            "profile_sid": ("profile.sid", "str"),
            "profile_diskencryptiontype": ("profile.diskEncryptionType", "str"),
            "profile_integrityjailbreak": ("profile.integrityJailbreak", "bool"),
            "profile_tpmpublickeyhash": ("profile.tpmPublicKeyHash", "str"),
            "resourcetype": ("resourceType", "str"),
            "resourcedisplayname_value": ("resourceDisplayName.value", "str"),
            "resourcedisplayname_sensitive": ("resourceDisplayName.sensitive", "bool"),
            "resourceid": ("resourceId", "str"),
            "resourcealternateid": ("resourceAlternateId", "str"),
        },
    },
    "device_users": {
        # Not derived_from "devices": Okta's device-users endpoint is a
        # separate per-device network call, not data nested inside a raw
        # device record, so it can't use record_path extraction. device_id
        # is injected into each raw record at fetch time (see
        # _fetch_device_users_page) since it isn't present in the API
        # response body itself.
        "endpoint": _DEVICE_USERS_PATH,
        "columns": {
            "device_id": ("_device_id", "str"),
            "created": ("created", "datetime"),
            "managementstatus": ("managementStatus", "str"),
            "screenlocktype": ("screenLockType", "str"),
            "user_id": ("user.id", "str"),
            "user_status": ("user.status", "str"),
            "user_displayname": ("user.displayName", "str"),
            "user_profile_login": ("user.profile.login", "str"),
            "user_created": ("user.created", "datetime"),
        },
    },
}


class OktaCollector(Collector):
    env_prefix = "OKTA"
    manifest = MANIFEST
    required_config_keys = ("domain", "token")

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        self._base_url = ""

    def _authenticate(self) -> None:
        self._base_url = self._config["domain"].rstrip("/")
        self._session.headers["Authorization"] = f"SSWS {self._config['token']}"
        self._session.headers["Accept"] = "application/json"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "users":
            return self._fetch_list_page(_USERS_PATH, kwargs, cursor)
        if resource == "devices":
            return self._fetch_list_page(_DEVICES_PATH, kwargs, cursor)
        if resource == "device_users":
            return self._fetch_device_users_page(kwargs, cursor)
        raise ValueError(f"Unsupported resource '{resource}'")

    def _fetch_list_page(
        self, path: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            response = self._get(cursor)
        else:
            params: dict[str, Any] = {"limit": _PAGE_LIMIT}
            params.update(kwargs)
            response = self._get(self._base_url + path, params=params)

        records = response.json()
        if not isinstance(records, list):
            records = []
        next_url = self._next_link(response)
        return records, next_url

    def _fetch_device_users_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        devices, next_devices_cursor = self._fetch_list_page(
            _DEVICES_PATH, kwargs, cursor
        )

        records: list[dict[str, Any]] = []
        for device in devices:
            device_id = device.get("id")
            if not device_id:
                continue
            records.extend(self._drain_device_users(device_id))

        return records, next_devices_cursor

    def _drain_device_users(self, device_id: str) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        url = self._base_url + _DEVICE_USERS_PATH.format(device_id=device_id)
        while url:
            response = self._get(url)
            body = response.json()
            if isinstance(body, list):
                for record in body:
                    record["_device_id"] = device_id
                    records.append(record)
            url = self._next_link(response)
        return records

    def _get(self, url: str, params: dict[str, Any] | None = None) -> Any:
        response = self._session.get(url, params=params, timeout=30)
        if response.status_code == 429:
            reset = response.headers.get("X-Rate-Limit-Reset")
            retry_after = max(int(reset) - int(time.time()) + 1, 1) if reset else None
            raise RateLimitedSignal(retry_after=retry_after)
        if response.status_code == 401:
            raise UnauthorizedSignal()
        if response.status_code != 200:
            logger.warning(
                "unexpected status code",
                extra={"source": "okta", "status_code": response.status_code},
            )
        response.raise_for_status()
        return response

    @staticmethod
    def _next_link(response: Any) -> str | None:
        link_header = response.headers.get("Link")
        if not link_header:
            return None
        match = _LINK_NEXT_RE.search(link_header)
        return match.group(1) if match else None
