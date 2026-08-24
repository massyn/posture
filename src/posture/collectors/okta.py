"""Okta collector.

Raw ``requests`` against the standard Okta REST API — no Okta SDK (its API
is generic REST with Link-header pagination; nothing here needs vendor
machinery the base class can't already generalise). Auth, retry, pagination,
caching, and reporting all come from the base Collector; this module only
knows Okta's endpoints and resource manifests.

Resources: ``users``, ``devices``, ``device_users``, ``groups``,
``group_members``, ``user_factors``, ``user_roles``. Audit ``logs`` were
deliberately left out of scope.
"""

from __future__ import annotations

import logging
import random
import re
import time
from typing import Any, ClassVar

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger = logging.getLogger("posture.collectors.okta")

# Scoped resources (device_users, group_members, user_factors, user_roles)
# fan out one network call per parent record. A handful of workers in
# parallel meaningfully cuts wall time without hammering Okta's per-endpoint
# rate limit into constant 429s. Kept low (vs. e.g. intune's 10) because
# Okta's limits are comparatively tight and a 429 is expected routinely
# under fan-out, not an edge case.
_MAX_FANOUT_WORKERS = 5

# A 429 on one parent's drain is handled locally (backoff + retry just that
# parent) rather than propagating and forcing base.py to retry the entire
# page — with up to 200 parents per page, discarding every sibling's
# already-fetched results over one rate-limited parent would be wasteful.
_MAX_DRAIN_RATE_LIMIT_RETRIES = 20
_DRAIN_BACKOFF_BASE_SECONDS = 1.0
_DRAIN_BACKOFF_CAP_SECONDS = 60.0

_USERS_PATH = "/api/v1/users"
_DEVICES_PATH = "/api/v1/devices"
_DEVICE_USERS_PATH = "/api/v1/devices/{device_id}/users"
_GROUPS_PATH = "/api/v1/groups"
_GROUP_MEMBERS_PATH = "/api/v1/groups/{group_id}/users"
_USER_FACTORS_PATH = "/api/v1/users/{user_id}/factors"
_USER_ROLES_PATH = "/api/v1/users/{user_id}/roles"

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
        # _fetch_scoped_page/_drain_scoped) since it isn't present in the
        # API response body itself.
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
    "groups": {
        "endpoint": _GROUPS_PATH,
        "columns": {
            "id": ("id", "str"),
            "type": ("type", "str"),
            "created": ("created", "datetime"),
            "last_updated": ("lastUpdated", "datetime"),
            "last_membership_updated": ("lastMembershipUpdated", "datetime"),
            "profile_name": ("profile.name", "str"),
            "profile_description": ("profile.description", "str"),
        },
    },
    "group_members": {
        # Not derived_from "groups": Okta's group-members endpoint is a
        # separate per-group network call returning member user objects,
        # not data nested inside a raw group record. group_id is injected
        # into each raw record at fetch time (see
        # _fetch_scoped_page/_drain_scoped) since it isn't present in the
        # API response body itself.
        "endpoint": _GROUP_MEMBERS_PATH,
        "columns": {
            "group_id": ("_group_id", "str"),
            "id": ("id", "str"),
            "status": ("status", "str"),
            "profile_login": ("profile.login", "str"),
            "profile_email": ("profile.email", "str"),
            "profile_first_name": ("profile.firstName", "str"),
            "profile_last_name": ("profile.lastName", "str"),
        },
    },
    "user_factors": {
        # Not derived_from "users": Okta's factors endpoint is a separate
        # per-user network call, not data nested inside a raw user record.
        # user_id is injected into each raw record at fetch time (see
        # _fetch_scoped_page/_drain_scoped) since it isn't present in the
        # API response body itself.
        "endpoint": _USER_FACTORS_PATH,
        "columns": {
            "user_id": ("_user_id", "str"),
            "id": ("id", "str"),
            "factor_type": ("factorType", "str"),
            "provider": ("provider", "str"),
            "vendor_name": ("vendorName", "str"),
            "status": ("status", "str"),
            "created": ("created", "datetime"),
            "last_updated": ("lastUpdated", "datetime"),
            "profile_phone_number": ("profile.phoneNumber", "str"),
            "profile_credential_id": ("profile.credentialId", "str"),
            "profile_authenticator_name": ("profile.authenticatorName", "str"),
            "profile_platform": ("profile.platform", "str"),
        },
    },
    "user_roles": {
        # Not derived_from "users": per-user network call, same shape as
        # user_factors. user_id is injected client-side (see
        # _fetch_scoped_page/_drain_scoped).
        "endpoint": _USER_ROLES_PATH,
        "columns": {
            "user_id": ("_user_id", "str"),
            "id": ("id", "str"),
            "label": ("label", "str"),
            "type": ("type", "str"),
            "status": ("status", "str"),
            "assignment_type": ("assignmentType", "str"),
            "created": ("created", "datetime"),
            "last_updated": ("lastUpdated", "datetime"),
        },
    },
}


class OktaCollector(Collector):
    env_prefix = "OKTA"
    display_name = "Okta"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {"domain": True, "token": True}

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
            return self._fetch_scoped_page(
                resource, _DEVICES_PATH, _DEVICE_USERS_PATH, "device_id", kwargs, cursor
            )
        if resource == "groups":
            return self._fetch_list_page(_GROUPS_PATH, kwargs, cursor)
        if resource == "group_members":
            return self._fetch_scoped_page(
                resource, _GROUPS_PATH, _GROUP_MEMBERS_PATH, "group_id", kwargs, cursor
            )
        if resource == "user_factors":
            return self._fetch_scoped_page(
                resource, _USERS_PATH, _USER_FACTORS_PATH, "user_id", kwargs, cursor
            )
        if resource == "user_roles":
            return self._fetch_scoped_page(
                resource, _USERS_PATH, _USER_ROLES_PATH, "user_id", kwargs, cursor
            )
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

    def _fetch_scoped_page(
        self,
        resource: str,
        parent_path: str,
        child_path_template: str,
        id_field: str,
        kwargs: dict[str, Any],
        cursor: Any,
    ) -> tuple[list[dict[str, Any]], Any]:
        parents, next_parents_cursor = self._fetch_list_page(
            parent_path, kwargs, cursor
        )

        parent_ids = [pid for p in parents if (pid := p.get("id"))]
        records = self._resumable_fanout(
            resource,
            parent_ids,
            lambda parent_id: self._drain_scoped(
                child_path_template, id_field, parent_id
            ),
            _MAX_FANOUT_WORKERS,
        )
        return records, next_parents_cursor

    def _drain_scoped(
        self, path_template: str, id_field: str, parent_id: str
    ) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        url = self._base_url + path_template.format(**{id_field: parent_id})
        rate_limit_attempt = 0
        while url:
            try:
                response = self._get(url)
            except RateLimitedSignal as exc:
                rate_limit_attempt += 1
                if rate_limit_attempt > _MAX_DRAIN_RATE_LIMIT_RETRIES:
                    raise
                wait = min(
                    exc.retry_after
                    or _DRAIN_BACKOFF_BASE_SECONDS * (2**rate_limit_attempt),
                    _DRAIN_BACKOFF_CAP_SECONDS,
                )
                # Jitter (+/-25%) so the fan-out's other workers, which likely
                # hit the same rate limit bucket around the same time, don't
                # all wake up and retry in lockstep.
                time.sleep(wait * random.uniform(0.75, 1.25))
                continue
            body = response.json()
            if isinstance(body, list):
                for record in body:
                    record[f"_{id_field}"] = parent_id
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
