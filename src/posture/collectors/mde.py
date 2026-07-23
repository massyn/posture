"""Microsoft Defender for Endpoint collector.

Raw ``requests`` against the Defender for Endpoint API — no vendor SDK. Auth
is Azure AD client-credentials (shared with ``intune.py`` via
``_azure_oauth.py``). Pagination is NOT the same for every resource here:

- ``/api/machines``, ``/api/vulnerabilities``, ``/api/deviceavinfo`` never
  return ``@odata.nextLink`` (confirmed against Microsoft's own docs, not
  assumed — see ``get-all-vulnerabilities`` and ``exposed-apis-odata-samples``).
  They support ``$top``/``$skip`` instead, so list pagination for these
  increments ``$skip`` and stops when a page returns fewer than ``$top``
  records.
- ``machine_vulnerabilities`` uses MDE's bulk export endpoint
  (``/api/machines/SoftwareVulnerabilitiesByMachine``), which DOES return
  ``@odata.nextLink`` — a complete, directly-callable URL for the next page
  — and has its own, much more generous rate limit (30 calls/minute, 1,000/
  hour) than the ~100/minute shared budget the rest of this collector paces
  against. One call returns every device's vulnerabilities in one grain
  (DeviceId x SoftwareVendor x SoftwareName x SoftwareVersion x CveId),
  replacing what used to be a per-machine fan-out (one request per device —
  infeasible at scale: tens of thousands of devices meant tens of thousands
  of requests against a ~100/minute budget). Requires the
  ``Vulnerability.Read.All`` application permission.

No incremental sync: the reference supports `$filter`-based checkpointing,
which conflicts with posture's locked "full pull, point in time, no
incremental sync, ever" decision. Every collect() here is a full snapshot.

Resources: ``machines``, ``vulnerabilities``, ``device_av_info``,
``machine_vulnerabilities``.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal
from posture.collectors._azure_oauth import fetch_azure_ad_token

logger = logging.getLogger("posture.collectors.mde")

_API_BASE_URL = "https://api.security.microsoft.com"
_PAGE_SIZE = 1000  # comfortably under the documented $top max of 8,000

# MDE's documented general API limit is ~100 calls/minute per app registration.
# Staying comfortably under that (0.65s between requests ~= 92/min) leaves
# headroom for other traffic against the same app registration.
_MIN_REQUEST_INTERVAL_SECONDS = 0.65

# Server-side max for machine_vulnerabilities' pageSize param is 200,000.
# Default kept well under that: 50k records/page at ~1KB/record (per MDE
# docs) is ~50MB of JSON per response, a reasonable balance against memory/
# retry cost of one giant page. Override via the 'page_size' kwarg if needed.
_MACHINE_VULN_PAGE_SIZE = 50_000

# MDE returns this .NET DateTime.MinValue sentinel for datetime fields that
# have never been set (e.g. quickScanTime on a device never AV-scanned).
# pandas' datetime64[ns] can't represent year 1, so it must be scrubbed to
# None here before parse() casts it — otherwise pd.to_datetime raises
# "Out of bounds nanosecond timestamp".
_EPOCH_PLACEHOLDER_PREFIX = "0001-01-01"


def _sanitize_epoch_placeholders(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for record in records:
        for key, value in record.items():
            if isinstance(value, str) and value.startswith(_EPOCH_PLACEHOLDER_PREFIX):
                record[key] = None
    return records


_ENDPOINTS = {
    "machines": "/api/machines",
    "vulnerabilities": "/api/vulnerabilities",
    "device_av_info": "/api/deviceavinfo",
    "machine_vulnerabilities": "/api/machines/SoftwareVulnerabilitiesByMachine",
}

MANIFEST: dict[str, dict[str, Any]] = {
    "machines": {
        "endpoint": _ENDPOINTS["machines"],
        "columns": {
            "machine_id": ("id", "str"),
            "device_name": ("computerDnsName", "str"),
            "os_platform": ("osPlatform", "str"),
            "os_version": ("version", "str"),
            "os_build": ("osBuild", "str"),
            "last_ip_address": ("lastIpAddress", "str"),
            "last_external_ip_address": ("lastExternalIpAddress", "str"),
            "agent_version": ("agentVersion", "str"),
            "health_status": ("healthStatus", "str"),
            "risk_score": ("riskScore", "str"),
            "exposure_level": ("exposureLevel", "str"),
            "last_seen": ("lastSeen", "datetime"),
            "first_seen": ("firstSeen", "datetime"),
            "rbac_group_name": ("rbacGroupName", "str"),
            "rbac_group_id": ("rbacGroupId", "str"),
            "aad_device_id": ("aadDeviceId", "str"),
            "device_value": ("deviceValue", "str"),
            "is_aad_joined": ("isAadJoined", "bool"),
            "onboarding_status": ("onboardingStatus", "str"),
            "managed_by": ("managedBy", "str"),
        },
    },
    "vulnerabilities": {
        "endpoint": _ENDPOINTS["vulnerabilities"],
        "columns": {
            "vulnerability_id": ("id", "str"),
            "vulnerability_name": ("name", "str"),
            "description": ("description", "str"),
            "severity": ("severity", "str"),
            "cvss_score": ("cvssV3", "float"),
            "cvss_vector": ("cvssVector", "str"),
            "exposed_machines": ("exposedMachines", "int"),
            "published_on": ("publishedOn", "datetime"),
            "updated_on": ("updatedOn", "datetime"),
            "first_detected": ("firstDetected", "datetime"),
            "patch_first_available": ("patchFirstAvailable", "datetime"),
            "public_exploit": ("publicExploit", "bool"),
            "exploit_verified": ("exploitVerified", "bool"),
            "exploit_in_kit": ("exploitInKit", "bool"),
            "epss": ("epss", "float"),
            "status": ("status", "str"),
        },
    },
    "device_av_info": {
        "endpoint": _ENDPOINTS["device_av_info"],
        "columns": {
            # The reference declares both "id" and "machineId" as sources for
            # machine_id; its own dedup logic keeps whichever is processed
            # first ("id", by dict insertion order) and skips the other, so
            # "id" is the one actually used at runtime. Matched here.
            "machine_id": ("id", "str"),
            "device_name": ("computerDnsName", "str"),
            "os_kind": ("osKind", "str"),
            "os_platform": ("osPlatform", "str"),
            "os_version": ("osVersion", "str"),
            "av_mode": ("avMode", "str"),
            "av_signature_version": ("avSignatureVersion", "str"),
            "av_engine_version": ("avEngineVersion", "str"),
            "av_platform_version": ("avPlatformVersion", "str"),
            "last_seen_time": ("lastSeenTime", "datetime"),
            "quick_scan_result": ("quickScanResult", "str"),
            "quick_scan_error": ("quickScanError", "str"),
            "quick_scan_time": ("quickScanTime", "datetime"),
            "full_scan_result": ("fullScanResult", "str"),
            "full_scan_error": ("fullScanError", "str"),
            "full_scan_time": ("fullScanTime", "datetime"),
            "data_refresh_timestamp": ("dataRefreshTimestamp", "datetime"),
            "av_engine_update_time": ("avEngineUpdateTime", "datetime"),
            "av_signature_update_time": ("avSignatureUpdateTime", "datetime"),
            "av_platform_update_time": ("avPlatformUpdateTime", "datetime"),
            "av_is_signature_up_to_date": ("avIsSignatureUpToDate", "bool"),
            "av_is_engine_up_to_date": ("avIsEngineUpToDate", "bool"),
            "av_is_platform_up_to_date": ("avIsPlatformUpToDate", "bool"),
            "av_signature_publish_time": ("avSignaturePublishTime", "datetime"),
            "av_signature_data_refresh_time": (
                "avSignatureDataRefreshTime",
                "datetime",
            ),
            "cloud_protection_state": ("cloudProtectionState", "str"),
            "av_mode_data_refresh_time": ("avModeDataRefreshTime", "datetime"),
            "rbac_group_name": ("rbacGroupName", "str"),
            "rbac_group_id": ("rbacGroupId", "str"),
        },
    },
    "machine_vulnerabilities": {
        "endpoint": _ENDPOINTS["machine_vulnerabilities"],
        "columns": {
            "machine_vulnerability_id": ("id", "str"),
            "machine_id": ("deviceId", "str"),
            "device_name": ("deviceName", "str"),
            "cve_id": ("cveId", "str"),
            "cvss_score": ("cvssScore", "float"),
            "vulnerability_severity_level": ("vulnerabilitySeverityLevel", "str"),
            "exploitability_level": ("exploitabilityLevel", "str"),
            "product_vendor": ("softwareVendor", "str"),
            "product_name": ("softwareName", "str"),
            "product_version": ("softwareVersion", "str"),
            "os_platform": ("osPlatform", "str"),
            "rbac_group_name": ("rbacGroupName", "str"),
            "rbac_group_id": ("rbacGroupId", "str"),
            "recommended_security_update": ("recommendedSecurityUpdate", "str"),
            "recommended_security_update_id": ("recommendedSecurityUpdateId", "str"),
            "security_update_available": ("securityUpdateAvailable", "bool"),
            "disk_paths": ("diskPaths", "json"),
            "registry_paths": ("registryPaths", "json"),
            "first_seen_timestamp": ("firstSeenTimestamp", "datetime"),
            "last_seen_timestamp": ("lastSeenTimestamp", "datetime"),
        },
    },
}


# ============================================================================
# TEMP-DEBUG: MDE non-200 diagnostic logging. Remove this whole block (and its
# call site in _get) once the root cause of MDE's failures has been found.
# Writes request/response detail for any non-200 response to error.log next
# to the CWD. Authorization header is redacted — never write secrets to disk.
# ============================================================================
_ERROR_LOG_PATH = "error.log"
_ERROR_LOG_LOCK = threading.Lock()


def _log_error_to_file(url: str, params: dict[str, Any] | None, response: Any) -> None:
    headers = {
        key: ("<redacted>" if key.lower() == "authorization" else value)
        for key, value in response.request.headers.items()
    }
    entry = (
        f"{time.strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
        f"URL: {url}\n"
        f"Status: {response.status_code}\n"
        f"Payload/params: {params!r}\n"
        f"Request headers: {headers!r}\n"
        f"Response body: {response.text}\n"
        f"{'-' * 80}\n"
    )
    with _ERROR_LOG_LOCK:
        with open(_ERROR_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(entry)


# ============================================================================
# END TEMP-DEBUG
# ============================================================================


class MdeCollector(Collector):
    env_prefix = "MDE"
    display_name = "Microsoft Defender for Endpoint"
    manifest = MANIFEST
    required_config_keys = ("tenant_id", "client_id", "client_secret")

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        self._rate_limit_lock = threading.Lock()
        self._last_request_time = 0.0

    def _authenticate(self) -> None:
        token = fetch_azure_ad_token(
            self._session,
            tenant_id=self._config["tenant_id"],
            client_id=self._config["client_id"],
            client_secret=self._config["client_secret"],
            scope="https://api.securitycenter.windows.com/.default",
            source="MDE",
        )
        self._session.headers["Authorization"] = f"Bearer {token}"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "machine_vulnerabilities":
            records, next_cursor = self._fetch_machine_vulnerabilities_page(
                kwargs, cursor
            )
        else:
            records, next_cursor = self._fetch_list_page(resource, kwargs, cursor)
        return _sanitize_epoch_placeholders(records), next_cursor

    def _fetch_machine_vulnerabilities_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        # cursor is the full "@odata.nextLink" URL from the previous page (or
        # None for the first page) — MDE documents this endpoint's nextLink as
        # a complete, directly-callable URL, unlike the $skip-based pagination
        # used elsewhere in this collector.
        if cursor is not None:
            response = self._get(cursor)
        else:
            page_size = kwargs.get("page_size", _MACHINE_VULN_PAGE_SIZE)
            url = _API_BASE_URL + _ENDPOINTS["machine_vulnerabilities"]
            response = self._get(url, params={"pageSize": page_size})

        payload = response.json()
        records = payload.get("value", [])
        next_cursor = payload.get("@odata.nextLink")
        return records, next_cursor

    def _fetch_list_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        skip = cursor if cursor is not None else 0
        params: dict[str, Any] = {"$top": _PAGE_SIZE, "$skip": skip}
        params.update(kwargs)

        response = self._get(_API_BASE_URL + _ENDPOINTS[resource], params=params)
        records = response.json().get("value", [])
        if not records:
            return [], None

        next_cursor = skip + _PAGE_SIZE if len(records) == _PAGE_SIZE else None
        return records, next_cursor

    def _pace_request(self) -> None:
        with self._rate_limit_lock:
            elapsed = time.monotonic() - self._last_request_time
            wait = _MIN_REQUEST_INTERVAL_SECONDS - elapsed
            if wait > 0:
                time.sleep(wait)
            self._last_request_time = time.monotonic()

    def _get(self, url: str, params: dict[str, Any] | None = None) -> Any:
        self._pace_request()
        response = self._session.get(url, params=params, timeout=60)
        if response.status_code != 200:
            _log_error_to_file(url, params, response)  # TEMP-DEBUG: remove once MDE failure root cause is found
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
                extra={"source": "mde", "status_code": response.status_code},
            )
        response.raise_for_status()
        return response
