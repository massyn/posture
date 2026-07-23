"""Crowdstrike Falcon collector.

Raw ``requests`` against the generic Falcon REST API — no FalconPy. Auth,
retry, pagination, caching, and reporting all come from the base Collector;
this module only knows Crowdstrike's endpoints and resource manifests.

Resources: ``hosts``, ``host_groups``, ``vulnerabilities`` (+ derived
``vulnerability_remediations``), ``zero_trust_assessment`` (+ derived
``zero_trust_assessment_os_signals`` and ``zero_trust_assessment_sensor_signals``).
"""

from __future__ import annotations

import logging
from typing import Any

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal
from posture.exceptions import AuthenticationError

logger = logging.getLogger("posture.collectors.crowdstrike")

_DEFAULT_TOKEN_URL = "https://api.crowdstrike.com/oauth2/token"
_DEVICES_QUERY_PATH = "/devices/queries/devices/v1"
_DEVICES_ENTITIES_PATH = "/devices/entities/devices/v2"
_SPOTLIGHT_VULNERABILITIES_PATH = "/spotlight/combined/vulnerabilities/v1"
_ZTA_ASSESSMENT_PATH = "/zero-trust-assessment/entities/assessments/v1"
_HOST_GROUPS_COMBINED_PATH = "/devices/combined/host-groups/v1"

_PAGE_LIMIT = 500
_VULN_PAGE_LIMIT = 400
_DEFAULT_VULN_FILTER = "cve.id:!['']+last_seen_within:'5'+status:['open','reopen']"

# Cloud region -> API base URL. Discovered dynamically from the X-Cs-Region
# header on the token response, not guessed or configured up front.
_REGION_BASE_URLS = {
    "us-1": "https://api.crowdstrike.com",
    "us-2": "https://api.us-2.crowdstrike.com",
    "eu-1": "https://api.eu-1.crowdstrike.com",
    "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
}

MANIFEST: dict[str, dict[str, Any]] = {
    "hosts": {
        "endpoint": _DEVICES_QUERY_PATH,
        "columns": {
            "client_id": ("cid", "str"),
            "device_id": ("device_id", "str"),
            "hostname": ("hostname", "str"),
            "kernel_version": ("kernel_version", "str"),
            "last_login_timestamp": ("last_login_timestamp", "datetime"),
            "local_ip": ("local_ip", "str"),
            "mac_address": ("mac_address", "str"),
            "last_login_uid": ("last_login_uid", "str"),
            "last_login_user": ("last_login_user", "str"),
            "first_seen": ("first_seen", "datetime"),
            "last_seen": ("last_seen", "datetime"),
            "os_build": ("os_build", "str"),
            "os_version": ("os_version", "str"),
            "platform_name": ("platform_name", "str"),
            "provision_status": ("provision_status", "str"),
            "reduced_functionality_mode": ("reduced_functionality_mode", "bool"),
            "serial_number": ("serial_number", "str"),
            "host_status": ("status", "str"),
            "system_manufacturer": ("system_manufacturer", "str"),
            "system_product_name": ("system_product_name", "str"),
        },
    },
    "host_groups": {
        "endpoint": _HOST_GROUPS_COMBINED_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "description": ("description", "str"),
            "group_type": ("group_type", "str"),
            "assignment_rule": ("assignment_rule", "str"),
            "created_by": ("created_by", "str"),
            "created_at": ("created_timestamp", "datetime"),
            "modified_by": ("modified_by", "str"),
            "modified_at": ("modified_timestamp", "datetime"),
        },
    },
    "vulnerabilities": {
        "endpoint": _SPOTLIGHT_VULNERABILITIES_PATH,
        "default_filter": _DEFAULT_VULN_FILTER,
        "columns": {
            # has_exploit / has_patch are deliberately omitted: they are
            # computed booleans (exploit_status >= 90, remediation_level == 'O')
            # in the reference implementation, not raw allowlisted fields.
            # posture's manifest is allowlist-only — interpretation belongs
            # downstream, never here.
            "id": ("id", "str"),
            "agent_id": ("aid", "str"),
            "client_id": ("cid", "str"),
            "status": ("status", "str"),
            "cve_id": ("cve.id", "str"),
            "description": ("cve.description", "str"),
            "exprt_rating": ("cve.exprt_rating", "str"),
            "remediation_level": ("cve.remediation_level", "str"),
            "severity": ("cve.severity", "str"),
            "vector": ("cve.vector", "str"),
            "created_at": ("created_timestamp", "datetime"),
            "updated_at": ("updated_timestamp", "datetime"),
            "published_on": ("cve.published_date", "datetime"),
            "spotlight_published_at": ("cve.spotlight_published_date", "datetime"),
            "is_cisa_kev": ("cve.cisa_info.is_cisa_kev", "bool"),
            "is_suppressed": ("suppression_info.is_suppressed", "bool"),
            "exploit_status": ("cve.exploit_status", "int"),
            "exploitability_score": ("cve.exploitability_score", "float"),
            "impact_score": ("cve.impact_score", "float"),
            "base_score": ("cve.base_score", "float"),
        },
    },
    "vulnerability_remediations": {
        "derived_from": "vulnerabilities",
        "record_path": "remediation.entities",
        "columns": {
            "id": ("$parent.id", "str"),
            "action": ("action", "str"),
            "entity_id": ("id", "str"),
            "link": ("link", "str"),
            "reference": ("reference", "str"),
            "title": ("title", "str"),
            "vendor_url": ("vendor_url", "str"),
        },
    },
    "zero_trust_assessment": {
        "endpoint": _ZTA_ASSESSMENT_PATH,
        "columns": {
            "aid": ("aid", "str"),
            "cid": ("cid", "str"),
            "system_serial_number": ("system_serial_number", "str"),
            "event_platform": ("event_platform", "str"),
            "product_type_desc": ("product_type_desc", "str"),
            "modified_time": ("modified_time", "datetime"),
            "sensor_file_status": ("sensor_file_status", "str"),
            "assessment_sensor_config": ("assessment.sensor_config", "int"),
            "assessment_overall": ("assessment.overall", "int"),
            "assessment_version": ("assessment.version", "str"),
        },
    },
    "zero_trust_assessment_os_signals": {
        "derived_from": "zero_trust_assessment",
        "record_path": "assessment_items.os_signals",
        "columns": {
            "aid": ("$parent.aid", "str"),
            "type": ("$literal:os_signals", "str"),
            "criteria": ("criteria", "str"),
            "group_name": ("group_name", "str"),
            "meets_criteria": ("meets_criteria", "str"),
            "signal_id": ("signal_id", "str"),
            "signal_name": ("signal_name", "str"),
        },
    },
    "zero_trust_assessment_sensor_signals": {
        "derived_from": "zero_trust_assessment",
        "record_path": "assessment_items.sensor_signals",
        "columns": {
            "aid": ("$parent.aid", "str"),
            "type": ("$literal:sensor_signals", "str"),
            "criteria": ("criteria", "str"),
            "group_name": ("group_name", "str"),
            "meets_criteria": ("meets_criteria", "str"),
            "signal_id": ("signal_id", "str"),
            "signal_name": ("signal_name", "str"),
        },
    },
}


class CrowdstrikeCollector(Collector):
    env_prefix = "CROWDSTRIKE"
    manifest = MANIFEST
    required_config_keys = ("client_id", "client_secret")

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        self._base_url = _REGION_BASE_URLS["us-1"]

    def _authenticate(self) -> None:
        response = self._session.post(
            _DEFAULT_TOKEN_URL,
            data={
                "client_id": self._config["client_id"],
                "client_secret": self._config["client_secret"],
            },
            timeout=30,
        )
        if response.status_code == 401:
            raise AuthenticationError(
                "Crowdstrike rejected client credentials",
                source="crowdstrike",
                hint="check CROWDSTRIKE_CLIENT_ID / CROWDSTRIKE_CLIENT_SECRET",
            )
        if response.status_code != 200:
            logger.warning(
                "unexpected status code",
                extra={"source": "crowdstrike", "status_code": response.status_code},
            )
        response.raise_for_status()

        region = response.headers.get("X-Cs-Region")
        if region in _REGION_BASE_URLS:
            self._base_url = _REGION_BASE_URLS[region]

        token = response.json()["access_token"]
        self._session.headers["Authorization"] = f"Bearer {token}"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "hosts":
            return self._fetch_hosts_page(kwargs, cursor)
        if resource == "host_groups":
            return self._fetch_host_groups_page(kwargs, cursor)
        if resource == "vulnerabilities":
            return self._fetch_vulnerabilities_page(kwargs, cursor)
        if resource == "zero_trust_assessment":
            return self._fetch_zta_page(kwargs, cursor)
        raise ValueError(f"Unsupported resource '{resource}'")

    def _fetch_hosts_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        device_ids, next_cursor = self._query_device_ids(kwargs, cursor)
        if not device_ids:
            return [], None

        entities_response = self._session.post(
            self._base_url + _DEVICES_ENTITIES_PATH,
            json={"ids": device_ids},
            timeout=30,
        )
        self._raise_for_transient_errors(entities_response)
        entities = entities_response.json().get("resources", [])
        return entities, next_cursor

    def _fetch_host_groups_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        params: dict[str, Any] = {"limit": _PAGE_LIMIT}
        if "filter" in kwargs:
            params["filter"] = kwargs["filter"]
        if cursor is not None:
            params["offset"] = cursor

        response = self._session.get(
            self._base_url + _HOST_GROUPS_COMBINED_PATH, params=params, timeout=30
        )
        self._raise_for_transient_errors(response)
        body = response.json()

        resources = body.get("resources", [])
        pagination = body.get("meta", {}).get("pagination", {})
        total = pagination.get("total", 0)
        offset = pagination.get("offset", 0)
        next_cursor = offset if offset < total else None
        return resources, next_cursor

    def _fetch_vulnerabilities_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        params: dict[str, Any] = {
            "filter": kwargs.get(
                "filter", MANIFEST["vulnerabilities"]["default_filter"]
            ),
            "sort": "updated_timestamp|asc",
            "limit": _VULN_PAGE_LIMIT,
            "facet": ["cve", "host_info", "remediation"],
        }
        if cursor:
            params["after"] = cursor

        response = self._session.get(
            self._base_url + _SPOTLIGHT_VULNERABILITIES_PATH, params=params, timeout=30
        )
        self._raise_for_transient_errors(response)
        body = response.json()

        resources = body.get("resources", [])
        after = body.get("meta", {}).get("pagination", {}).get("after")
        next_cursor = after if resources and after else None
        return resources, next_cursor

    def _fetch_zta_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        # CANDIDATE: promote a shared "collect hosts, then batch-call an
        # entity endpoint against their ids" helper if a third resource
        # needs the same shape — this re-runs device-id discovery
        # independently of the hosts resource.
        device_ids, next_cursor = self._query_device_ids(kwargs, cursor)
        if not device_ids:
            return [], None

        assessment_response = self._session.get(
            self._base_url + _ZTA_ASSESSMENT_PATH,
            params={"ids": device_ids},
            timeout=30,
        )
        self._raise_for_transient_errors(assessment_response)
        assessments = assessment_response.json().get("resources", [])
        return assessments, next_cursor

    def _query_device_ids(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[str], Any]:
        params: dict[str, Any] = {"limit": _PAGE_LIMIT}
        if "filter" in kwargs:
            params["filter"] = kwargs["filter"]
        if cursor is not None:
            params["offset"] = cursor

        response = self._session.get(
            self._base_url + _DEVICES_QUERY_PATH, params=params, timeout=30
        )
        self._raise_for_transient_errors(response)
        body = response.json()

        device_ids: list[str] = body.get("resources", [])
        pagination = body.get("meta", {}).get("pagination", {})
        total = pagination.get("total", 0)
        offset = pagination.get("offset", 0)
        next_cursor = offset if offset < total else None
        return device_ids, next_cursor

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
                extra={"source": "crowdstrike", "status_code": response.status_code},
            )
        response.raise_for_status()
