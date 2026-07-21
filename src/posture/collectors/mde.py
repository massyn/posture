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
tripping MDE's rate limit hard). A `RateLimitedSignal` raised outside the
per-machine fan-out loop (e.g. list pagination) still propagates to base.py's
batch-level retry, which halves concurrency on each retry of this resource,
see ``_fetch_machine_vulnerabilities_page`` — see CLAUDE.md "Performance:
per-item fan-out" for the pattern shared with Intune's per-id detail lookups
and UpGuard's ``vendor_risks``.

All requests (list pagination and the per-machine fan-out alike) are paced
client-side to stay under MDE's documented ~100 calls/minute per-app-registration
limit (see ``_pace_request``), reducing how often 429s happen in the first
place — but pacing alone can't guarantee zero 429s (the budget may already be
partly consumed by other calls against the same app registration), so a 5xx,
429, or 401 for a single machine (e.g. a stale/decommissioned device record,
one unlucky request against a shared quota, or a machine outside this app
registration's RBAC scope) is handled locally per-machine — see
``_fetch_all_vulns_for_machine`` — with its own retry budget, rather than
propagating up to base.py's batch-level retry, which would otherwise cancel
and discard every machine already fetched by the rest of the fan-out just
because one machine got throttled, errored, or 401'd. A 401 gets exactly one
reauth-and-retry (single-flight across threads, see ``_reauth_once``) so a
genuinely expired shared token is still recovered — if the retry with a
guaranteed-fresh token still 401s, that's specific to the one machine and
it's skipped, not treated as a session-wide auth failure.

Resources: ``machines``, ``vulnerabilities``, ``device_av_info``,
``machine_vulnerabilities`` (requires machines ids).
"""

from __future__ import annotations

import concurrent.futures
import logging
import random
import threading
import time
from typing import Any

import requests

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal
from posture.collectors._azure_oauth import fetch_azure_ad_token

logger = logging.getLogger("posture.collectors.mde")

_API_BASE_URL = "https://api.security.microsoft.com"
_PAGE_SIZE = 1000  # comfortably under the documented $top max of 8,000
_DEFAULT_MACHINE_VULN_MAX_WORKERS = 10

# A lone machine 500ing is a per-device MDE fault, not a whole-tenant problem
# (unlike 429/401, which are meaningful at the batch level and handled by
# base.py's _request_with_retry). Retrying the entire fan-out for one bad
# machine would burn the shared retry budget and re-halve concurrency for
# every other machine, so a 5xx for a single machine is retried locally here
# and, if it still fails, that machine is skipped rather than failing the
# whole 'machine_vulnerabilities' resource.
_MACHINE_VULN_SERVER_ERROR_RETRIES = 2
_MACHINE_VULN_SERVER_ERROR_WAIT_SECONDS = 60.0

# A 429 for a single machine is handled the same way as a 5xx: locally, per
# machine, rather than propagating up to base.py's batch-level retry — that
# retry redoes the *entire* fan-out (base.py's all-or-nothing contract),
# which on a large tenant means throwing away hours of already-fetched
# machines over one throttled request. High retry budget (not infinite) so a
# permanently broken quota still eventually surfaces rather than looping
# forever; backoff mirrors base.py's (exponential, capped, jittered).
_MACHINE_VULN_RATE_LIMIT_MAX_RETRIES = 100
_MACHINE_VULN_RATE_LIMIT_BACKOFF_BASE_SECONDS = 1.0
_MACHINE_VULN_RATE_LIMIT_BACKOFF_CAP_SECONDS = 60.0

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
        # "requires" tells base.py to cache machines' raw records for this
        # instance's lifetime, since _fetch_machine_vulnerabilities_page reads
        # them again internally (see base.py::_get_raw for derived_from vs
        # requires).
        "requires": "machines",
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
        # Single-flight reauth for the machine_vulnerabilities fan-out: when the
        # shared token genuinely expires mid-run, every in-flight worker gets a
        # 401 near-simultaneously. Without coordination each of those threads
        # would call _authenticate() independently. The epoch counter makes only
        # the first thread to observe a given epoch perform the reauth; every
        # other thread that raced in on the same stale epoch just waits on the
        # lock and then re-checks (its retry uses the now-refreshed header).
        self._reauth_lock = threading.Lock()
        self._reauth_epoch = 0

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

    def _reauth_once(self, seen_epoch: int) -> None:
        with self._reauth_lock:
            if self._reauth_epoch == seen_epoch:
                self._authenticate()
                self._reauth_epoch += 1

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
            try:
                for future in concurrent.futures.as_completed(futures):
                    machine_id = futures[future]
                    records = future.result()
                    for record in records:
                        record["_machine_id"] = machine_id
                    all_records.extend(records)
            except BaseException:
                # A worker failed (e.g. token expired mid-run, raising
                # UnauthorizedSignal). Cancel every future that hasn't started
                # yet so the pool doesn't keep burning through the remaining
                # queue against a dead token before __exit__'s shutdown(wait=True)
                # can return control to base.py's retry/reauth handler.
                for pending in futures:
                    pending.cancel()
                raise

        # Reset once this run succeeds, so the halving only ever applies
        # across retries of a single collection — not to every subsequent
        # 'machine_vulnerabilities' call made against this instance.
        self._machine_vuln_attempt = 0
        return all_records, None

    def _fetch_all_vulns_for_machine(self, machine_id: str) -> list[dict[str, Any]]:
        # No $top/$skip/nextLink documented for this endpoint — it's a
        # single, complete response (unlike the org-wide list endpoints).
        endpoint = _ENDPOINTS["machine_vulnerabilities"].format(id=machine_id)
        attempt = 0
        rate_limit_attempt = 0
        reauthenticated = False
        while True:
            try:
                response = self._get(_API_BASE_URL + endpoint)
                return response.json().get("value", [])
            except UnauthorizedSignal:
                # A single machine 401ing is handled here, not by letting it
                # propagate to base.py's batch-level retry — that would cancel
                # every other in-flight machine and redo the *entire* fan-out
                # (potentially thousands of already-fetched machines) for what
                # is often just this one device's RBAC scope/licensing, not a
                # dead token. Reauth once (single-flight across threads, see
                # _reauth_once) and retry this machine; if it's still 401
                # after a guaranteed-fresh token, it's this machine, not the
                # session — skip it and let the rest of the fan-out proceed.
                if reauthenticated:
                    logger.warning(
                        "machine_vulnerabilities: skipping machine after "
                        "unauthorized even with a fresh token",
                        extra={
                            "source": self.env_prefix.lower(),
                            "machine_id": machine_id,
                        },
                    )
                    return []
                logger.debug(
                    "machine_vulnerabilities: unauthorized for machine, "
                    "reauthenticating and retrying",
                    extra={
                        "source": self.env_prefix.lower(),
                        "machine_id": machine_id,
                    },
                )
                self._reauth_once(self._reauth_epoch)
                reauthenticated = True
            except RateLimitedSignal as exc:
                rate_limit_attempt += 1
                if rate_limit_attempt > _MACHINE_VULN_RATE_LIMIT_MAX_RETRIES:
                    logger.warning(
                        "machine_vulnerabilities: skipping machine after "
                        "repeated rate limiting",
                        extra={
                            "source": self.env_prefix.lower(),
                            "machine_id": machine_id,
                            "attempts": rate_limit_attempt,
                        },
                    )
                    return []
                wait = min(
                    exc.retry_after
                    or _MACHINE_VULN_RATE_LIMIT_BACKOFF_BASE_SECONDS
                    * (2**rate_limit_attempt),
                    _MACHINE_VULN_RATE_LIMIT_BACKOFF_CAP_SECONDS,
                )
                logger.debug(
                    "machine_vulnerabilities: rate limited for machine, retrying",
                    extra={
                        "source": self.env_prefix.lower(),
                        "machine_id": machine_id,
                        "attempt": rate_limit_attempt,
                        "wait": wait,
                    },
                )
                time.sleep(wait * random.uniform(0.75, 1.25))
            except requests.exceptions.HTTPError as exc:
                status = exc.response.status_code if exc.response is not None else None
                if status == 404:
                    # Machine-specific endpoint: a 404 means this machine has
                    # no vulnerability data (e.g. offboarded since the machine
                    # list was pulled), not a collection-wide failure.
                    logger.info(
                        "machine_vulnerabilities: no data for machine (404), skipping",
                        extra={
                            "source": self.env_prefix.lower(),
                            "machine_id": machine_id,
                        },
                    )
                    return []
                if status is None or status < 500:
                    raise
                attempt += 1
                if attempt > _MACHINE_VULN_SERVER_ERROR_RETRIES:
                    logger.warning(
                        "machine_vulnerabilities: skipping machine after repeated "
                        "server errors",
                        extra={
                            "source": self.env_prefix.lower(),
                            "machine_id": machine_id,
                            "status": status,
                            "attempts": attempt,
                        },
                    )
                    return []
                logger.warning(
                    "machine_vulnerabilities: server error for machine, retrying",
                    extra={
                        "source": self.env_prefix.lower(),
                        "machine_id": machine_id,
                        "status": status,
                        "attempt": attempt,
                    },
                )
                time.sleep(_MACHINE_VULN_SERVER_ERROR_WAIT_SECONDS)

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
