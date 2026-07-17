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
pool (there can be thousands of machines; the reference uses 25 workers) —
the second posture resource, after UpGuard's ``vendor_risks``, that does
concurrent per-parent network calls rather than sequential pagination.

Resources: ``machines``, ``vulnerabilities``, ``device_av_info``,
``machine_vulnerabilities`` (requires machines ids).
"""

from __future__ import annotations

import concurrent.futures
from typing import Any

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal
from posture.collectors._azure_oauth import fetch_azure_ad_token

_API_BASE_URL = "https://api.security.microsoft.com"
_PAGE_SIZE = 1000  # comfortably under the documented $top max of 8,000
_DEFAULT_MACHINE_VULN_MAX_WORKERS = 25

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
            return self._fetch_machine_vulnerabilities_page(kwargs, cursor)
        return self._fetch_list_page(resource, kwargs, cursor)

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
        workers = max(1, min(max_workers, len(machine_ids)))

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
