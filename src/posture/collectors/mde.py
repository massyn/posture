"""Microsoft Defender for Endpoint collector.

Raw ``requests`` against the Defender for Endpoint API — no vendor SDK. Auth
is Azure AD client-credentials (shared with ``intune.py`` via
``_azure_oauth.py``). Pagination is NOT the same as Graph's here: MDE's
``/api/machines`` and ``/api/vulnerabilities`` never return
``@odata.nextLink`` (confirmed against Microsoft's own docs, not assumed —
see ``get-all-vulnerabilities`` and ``exposed-apis-odata-samples``). They
support ``$top``/``$skip`` instead, so list pagination here increments
``$skip`` and stops when a page returns fewer than ``$top`` records.
``/api/machines/{id}/vulnerabilities`` documents no pagination parameters at
all — treated as a single, complete response.

No incremental sync: the reference supports `$filter`-based checkpointing,
which conflicts with posture's locked "full pull, point in time, no
incremental sync, ever" decision. Every collect() here is a full snapshot.

``machine_vulnerabilities`` fans a request out per machine across a thread
pool (there can be thousands of machines; defaults to 10 workers — lowered
from the reference implementation's 25 after large tenants were observed
tripping MDE's rate limit hard enough to exhaust the whole batch's retry
budget; it also halves again on each retry of this resource, see
``_fetch_machine_vulnerabilities_page``) — see CLAUDE.md "Performance:
per-item fan-out" for the pattern shared with Intune's per-id detail lookups
and UpGuard's ``vendor_risks``.

All requests (list pagination and the per-machine fan-out alike) are paced
client-side to stay under MDE's documented ~100 calls/minute per-app-registration
limit (see ``_pace_request``) — without it, concurrent fan-out workers burst
past the limit in the first instant, and because a RateLimitedSignal redoes
the *entire* fan-out from scratch (base.py's all-or-nothing retry contract),
each retry just re-bursts at lower concurrency instead of avoiding the 429s
in the first place. This is the same root cause and fix as the KnowBe4
collector's ``_pace_request``.

Resources: ``machines``, ``vulnerabilities``, ``device_av_info``,
``machine_vulnerabilities`` (requires machines ids).
"""

from __future__ import annotations

import concurrent.futures
import threading
import time
from typing import Any

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal
from posture.collectors._azure_oauth import fetch_azure_ad_token

_API_BASE_URL = "https://api.security.microsoft.com"
_PAGE_SIZE = 1000  # comfortably under the documented $top max of 8,000
_DEFAULT_MACHINE_VULN_MAX_WORKERS = 10

# MDE's documented general API limit is ~100 calls/minute per app registration.
# Staying comfortably under that (0.65s between requests ~= 92/min) leaves
# headroom for other traffic against the same app registration.
_MIN_REQUEST_INTERVAL_SECONDS = 0.65

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
    "machine_vulnerabilities": "/api/machines/{id}/vulnerabilities",
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
        # Not derived_from "machines": each machine's vulnerabilities are
        # their own paginated network call, fanned out across a thread pool,
        # not data nested inside a raw machine record. _machine_id is
        # injected client-side (see _fetch_machine_vulnerabilities_page).
        "endpoint": _ENDPOINTS["machine_vulnerabilities"],
        "columns": {
            "machine_vulnerability_id": ("id", "str"),
            "cve_id": ("cveId", "str"),
            "machine_id": ("_machine_id", "str"),
            "fixing_kb_id": ("fixingKbId", "str"),
            "product_name": ("productName", "str"),
            "product_vendor": ("productVendor", "str"),
            "product_version": ("productVersion", "str"),
            "severity": ("severity", "str"),
        },
    },
}


class MdeCollector(Collector):
    env_prefix = "MDE"
    manifest = MANIFEST
    required_config_keys = ("tenant_id", "client_id", "client_secret")

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        # Retries of 'machine_vulnerabilities' (see _fetch_machine_vulnerabilities_page)
        # halve concurrency each attempt — tracked per-instance since base.py's
        # _request_with_retry redoes the whole batch on RateLimitedSignal without
        # telling the collector which attempt this is.
        self._machine_vuln_attempt = 0
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

    def _fetch_machine_vulnerabilities_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # entire fan-out already completed on first call

        machine_ids = kwargs.get("machine_ids")
        if machine_ids is None:
            raw_machines = self._get_raw("machines", {})
            machine_ids = [
                str(m["id"]) for m in raw_machines if m.get("id") is not None
            ]
        if not machine_ids:
            return [], None

        max_workers = kwargs.get("max_workers", _DEFAULT_MACHINE_VULN_MAX_WORKERS)
        # Each retry of this resource halves concurrency — a tenant large enough
        # to trip the rate limit at N workers is likely to trip it again at N on
        # the very next attempt otherwise, burning through the retry budget
        # without ever backing off the thing that caused it.
        effective_max_workers = max(1, max_workers // (2**self._machine_vuln_attempt))
        self._machine_vuln_attempt += 1
        workers = max(1, min(effective_max_workers, len(machine_ids)))

        all_records: list[dict[str, Any]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(
                    self._fetch_all_vulns_for_machine, machine_id
                ): machine_id
                for machine_id in machine_ids
            }
            for future in concurrent.futures.as_completed(futures):
                machine_id = futures[future]
                records = future.result()
                for record in records:
                    record["_machine_id"] = machine_id
                all_records.extend(records)

        return all_records, None

    def _fetch_all_vulns_for_machine(self, machine_id: str) -> list[dict[str, Any]]:
        # No $top/$skip/nextLink documented for this endpoint — it's a
        # single, complete response (unlike the org-wide list endpoints).
        endpoint = _ENDPOINTS["machine_vulnerabilities"].format(id=machine_id)
        response = self._get(_API_BASE_URL + endpoint)
        return response.json().get("value", [])

    def _pace_request(self) -> None:
        # Shared across threads so concurrent machine_vulnerabilities workers
        # can't collectively exceed the per-minute ceiling even though each
        # thread only knows about its own requests.
        with self._rate_limit_lock:
            elapsed = time.monotonic() - self._last_request_time
            wait = _MIN_REQUEST_INTERVAL_SECONDS - elapsed
            if wait > 0:
                time.sleep(wait)
            self._last_request_time = time.monotonic()

    def _get(self, url: str, params: dict[str, Any] | None = None) -> Any:
        self._pace_request()
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
