"""UpGuard collector.

Raw ``requests`` against the UpGuard Cyber Risk public API — no vendor SDK.
Auth, retry (429/401/connection-error), and reporting come from the base
Collector. Pagination and the ``vendor_risks`` per-vendor fan-out are handled
entirely inside this module (anti-overfitting: nothing here is promoted to
``base.py`` until a second collector demonstrably needs concurrent per-parent
fan-out).

List endpoints (``vendors``, ``domains``, ``breached_identities``) use
UpGuard's real cursor-based pagination: request ``page_token``/``page_size``,
response carries the next cursor in ``next_page_token`` (absent when
exhausted). ``/risks/vendors`` (``vendor_risks``) is not paginated at all —
one call per vendor returns that vendor's full risk list.

Resources: ``vendors``, ``domains``, ``breached_identities``, ``organisation``,
``vendor_risks``.
"""

from __future__ import annotations

import concurrent.futures
import logging
import os
import time
from typing import Any

import requests

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger = logging.getLogger("posture.upguard")

_DEFAULT_BASE_URL = "https://au.cyber-risk.upguard.com/api/public"
_PAGE_SIZE = 1000
_DEFAULT_RISKS_MAX_WORKERS = 8

# Per-vendor retry budget inside the vendor_risks thread pool. This is
# deliberately separate from base.py's outer retry: a 429/timeout on one
# vendor must not blow up the entire fan-out and restart every vendor's
# work from scratch (that combinatorial-restart is what made this
# collection take "way too long" — a single slow/rate-limited vendor kept
# triggering a full re-fetch of all ~hundreds of vendors, repeatedly).
_MAX_HOSTNAME_RETRIES = 5
_BACKOFF_BASE_SECONDS = 1.0
_BACKOFF_CAP_SECONDS = 60.0
_TRANSIENT_ERRORS = (
    requests.exceptions.ConnectionError,
    requests.exceptions.Timeout,
    requests.exceptions.ChunkedEncodingError,
)

MANIFEST: dict[str, dict[str, Any]] = {
    "vendors": {
        "endpoint": "/vendors",
        "columns": {
            "vendor_id": ("id", "str"),
            "vendor_name": ("name", "str"),
            "primary_hostname": ("primary_hostname", "str"),
            "score": ("score", "int"),
            "overall_score": ("overallScore", "int"),
            "automated_score": ("automatedScore", "int"),
            "website_security_score": ("category_scores.websiteSecurity", "int"),
            "email_security_score": ("category_scores.emailSecurity", "int"),
            "network_security_score": ("category_scores.networkSecurity", "int"),
            "ip_domain_reputation_score": (
                "category_scores.ipDomainReputation",
                "int",
            ),
            "operational_risk_score": ("category_scores.operationalRisk", "int"),
            "attack_surface_score": ("category_scores.attackSurface", "int"),
            "vulnerability_management_score": (
                "category_scores.vulnerabilityManagement",
                "int",
            ),
            "encryption_score": ("category_scores.encryption", "int"),
            "dns_score": ("category_scores.dns", "int"),
            "data_leakage_score": ("category_scores.dataLeakage", "int"),
            "brand_reputation_score": ("category_scores.brandReputation", "int"),
            "tier": ("tier", "str"),
            "monitored": ("monitored", "bool"),
            "assessment_status": ("assessmentStatus", "str"),
            "last_assessed": ("lastAssessed", "datetime"),
        },
    },
    "domains": {
        "endpoint": "/domains",
        "columns": {
            "domain_hostname": ("hostname", "str"),
            "active": ("active", "bool"),
            "primary_domain": ("primary_domain", "bool"),
        },
    },
    "breached_identities": {
        "endpoint": "/breaches",
        "columns": {
            "breached_identity_id": ("id", "str"),
            "identity_name": ("name", "str"),
            "domain": ("domain", "str"),
            "last_breach_date": ("last_breach_date", "datetime"),
            "num_breaches": ("num_breaches", "int"),
            "vip": ("vip", "bool"),
            "ignored": ("ignored", "bool"),
            "severity": ("severity", "str"),
        },
    },
    "organisation": {
        "endpoint": "/organisation",
        "columns": {
            "organisation_id": ("id", "str"),
            "organisation_name": ("name", "str"),
            "primary_hostname": ("primary_hostname", "str"),
            "automated_score": ("automatedScore", "int"),
            "website_security_score": ("categoryScores.websiteSecurity", "int"),
            "email_security_score": ("categoryScores.emailSecurity", "int"),
            "network_security_score": ("categoryScores.networkSecurity", "int"),
            "ip_domain_reputation_score": (
                "categoryScores.ipDomainReputation",
                "int",
            ),
            "operational_risk_score": ("categoryScores.operationalRisk", "int"),
            "attack_surface_score": ("categoryScores.attackSurface", "int"),
            "vulnerability_management_score": (
                "categoryScores.vulnerabilityManagement",
                "int",
            ),
            "encryption_score": ("categoryScores.encryption", "int"),
            "dns_score": ("categoryScores.dns", "int"),
            "data_leakage_score": ("categoryScores.dataLeakage", "int"),
            "brand_reputation_score": ("categoryScores.brandReputation", "int"),
        },
    },
    "vendor_risks": {
        # Not derived_from "vendors": each vendor requires its own (single,
        # unpaginated) network call, fanned out across a thread pool —
        # UpGuard's /risks/vendors sweep regularly takes 1-60s per vendor
        # across ~400 vendors — not data nested inside a raw vendor record.
        # requested_primary_hostname is injected client-side (see
        # _fetch_vendor_risks_page), not present in the API response.
        "endpoint": "/risks/vendors",
        "columns": {
            "risk_id": ("id", "str"),
            "finding": ("finding", "str"),
            "risk_description": ("description", "str"),
            "severity": ("severity", "str"),
            "category": ("category", "str"),
            "first_detected": ("firstDetected", "datetime"),
            "requested_primary_hostname": ("_requested_primary_hostname", "str"),
        },
    },
}


class UpGuardCollector(Collector):
    env_prefix = "UPGUARD"
    manifest = MANIFEST
    required_config_keys = ("api_key",)

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._base_url = (
            (config or {}).get("base_url")
            or os.environ.get("UPGUARD_BASE_URL")
            or _DEFAULT_BASE_URL
        ).rstrip("/")

    def _authenticate(self) -> None:
        self._session.headers["Accept"] = "application/json"
        self._session.headers["Authorization"] = self._config["api_key"]

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "organisation":
            return self._fetch_single_object_page(resource, cursor)
        if resource == "vendor_risks":
            return self._fetch_vendor_risks_page(kwargs, cursor)
        return self._fetch_list_page(resource, kwargs, cursor)

    def _fetch_single_object_page(
        self, resource: str, cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None
        endpoint = self.manifest[resource]["endpoint"]
        response = self._get(self._base_url + endpoint)
        return [response.json()], None

    def _fetch_list_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        endpoint = self.manifest[resource]["endpoint"]
        params: dict[str, Any] = {"page_size": _PAGE_SIZE}
        if cursor is not None:
            params["page_token"] = cursor
        params.update(kwargs)

        response = self._get(self._base_url + endpoint, params=params)
        payload = response.json()
        records = self._extract_records(resource, payload)
        next_cursor = payload.get("next_page_token") if isinstance(payload, dict) else None
        return records, next_cursor or None

    def _fetch_vendor_risks_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # entire fan-out already completed on first call

        hostnames = kwargs.get("hostnames")
        if hostnames is None:
            hostnames = self._all_vendor_hostnames()
        max_workers = kwargs.get("max_workers", _DEFAULT_RISKS_MAX_WORKERS)
        min_severity = kwargs.get("min_severity")

        if not hostnames:
            return [], None

        all_records: list[dict[str, Any]] = []
        truncated_hostnames: list[str] = []
        workers = max(1, min(max_workers, len(hostnames)))
        started_at = time.monotonic()
        completed = 0
        log_every = max(1, len(hostnames) // 20)  # ~20 progress lines total

        logger.info(
            "vendor_risks fan-out starting: %d vendors, %d workers",
            len(hostnames),
            workers,
            extra={
                "source": "upguard",
                "vendor_count": len(hostnames),
                "max_workers": workers,
            },
        )

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(
                    self._fetch_risks_for_hostname, hostname, min_severity
                ): hostname
                for hostname in hostnames
            }
            for future in concurrent.futures.as_completed(futures):
                hostname = futures[future]
                records, truncated = future.result()
                for record in records:
                    record["_requested_primary_hostname"] = hostname
                all_records.extend(records)
                if truncated:
                    truncated_hostnames.append(hostname)

                completed += 1
                logger.debug(
                    "vendor_risks vendor complete: %s (%d records, truncated=%s)",
                    hostname,
                    len(records),
                    truncated,
                    extra={
                        "source": "upguard",
                        "hostname": hostname,
                        "records": len(records),
                        "truncated": truncated,
                    },
                )
                if completed % log_every == 0 or completed == len(hostnames):
                    elapsed = time.monotonic() - started_at
                    logger.info(
                        "vendor_risks progress: %d/%d vendors, %d records so far, "
                        "%.1fs elapsed",
                        completed,
                        len(hostnames),
                        len(all_records),
                        elapsed,
                        extra={
                            "source": "upguard",
                            "completed": completed,
                            "total": len(hostnames),
                            "records_so_far": len(all_records),
                            "elapsed_seconds": round(elapsed, 1),
                        },
                    )

        if truncated_hostnames:
            logger.warning(
                "vendor_risks incomplete for %d hosts (page cap hit or retries "
                "exhausted) — data loss, not a fatal error: %s",
                len(truncated_hostnames),
                truncated_hostnames,
                extra={"source": "upguard", "hostnames": truncated_hostnames},
            )

        logger.info(
            "vendor_risks fan-out complete: %d vendors, %d records, %d truncated, "
            "%.1fs elapsed",
            len(hostnames),
            len(all_records),
            len(truncated_hostnames),
            time.monotonic() - started_at,
            extra={
                "source": "upguard",
                "vendor_count": len(hostnames),
                "records": len(all_records),
                "truncated_count": len(truncated_hostnames),
                "elapsed_seconds": round(time.monotonic() - started_at, 1),
            },
        )

        return all_records, None

    def _fetch_risks_for_hostname(
        self, hostname: str, min_severity: str | None
    ) -> tuple[list[dict[str, Any]], bool]:
        """Fetch one vendor's risks. /risks/vendors is not paginated — one
        call returns the vendor's full risk list. Never raises: a single
        vendor's 429/timeout/connection failure must not blow up the whole
        thread pool and force base.py to restart every vendor's work from
        scratch. Returns (records, truncated) — truncated means retries
        were exhausted and this vendor's risks were not retrieved."""
        params: dict[str, Any] = {"primary_hostname": hostname}
        if min_severity is not None:
            params["min_severity"] = min_severity

        rate_limit_attempt = 0
        connection_attempt = 0

        while True:
            try:
                response = self._get(self._base_url + "/risks/vendors", params=params)
            except RateLimitedSignal as exc:
                rate_limit_attempt += 1
                if rate_limit_attempt > _MAX_HOSTNAME_RETRIES:
                    logger.warning(
                        "giving up on vendor %s after rate-limit retries exhausted",
                        hostname,
                        extra={"source": "upguard", "hostname": hostname},
                    )
                    return [], True
                wait = min(
                    exc.retry_after
                    or _BACKOFF_BASE_SECONDS * (2**rate_limit_attempt),
                    _BACKOFF_CAP_SECONDS,
                )
                logger.debug(
                    "vendor_risks rate-limited on %s, attempt %d, backing off %.1fs",
                    hostname,
                    rate_limit_attempt,
                    wait,
                    extra={
                        "source": "upguard",
                        "hostname": hostname,
                        "attempt": rate_limit_attempt,
                        "wait_seconds": wait,
                    },
                )
                time.sleep(wait)
                continue
            except _TRANSIENT_ERRORS as exc:
                connection_attempt += 1
                if connection_attempt > _MAX_HOSTNAME_RETRIES:
                    logger.warning(
                        "giving up on vendor %s after connection retries "
                        "exhausted: %s",
                        hostname,
                        exc,
                        extra={
                            "source": "upguard",
                            "hostname": hostname,
                            "error": str(exc),
                        },
                    )
                    return [], True
                wait = min(_BACKOFF_BASE_SECONDS * (2**connection_attempt), 30.0)
                logger.debug(
                    "vendor_risks connection error on %s, attempt %d, backing off "
                    "%.1fs",
                    hostname,
                    connection_attempt,
                    wait,
                    extra={
                        "source": "upguard",
                        "hostname": hostname,
                        "attempt": connection_attempt,
                        "wait_seconds": wait,
                    },
                )
                time.sleep(wait)
                continue

            return self._extract_records("vendor_risks", response.json()), False

    def _all_vendor_hostnames(self) -> list[str]:
        raw_vendors = self._get_raw("vendors", {})
        hostnames: list[str] = []
        for vendor in raw_vendors:
            hostname = str(vendor.get("primary_hostname", "")).strip()
            if hostname and hostname not in hostnames:
                hostnames.append(hostname)
        return hostnames

    @staticmethod
    def _extract_records(resource: str, payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            response_key = {
                "vendors": "vendors",
                "domains": "domains",
                "breached_identities": "breached_identities",
                "vendor_risks": "risks",
            }.get(resource)
            if response_key:
                return payload.get(response_key, []) or []
        return []

    def _get(self, url: str, params: dict[str, Any] | None = None) -> Any:
        response = self._session.get(url, params=params, timeout=60)
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
                extra={"source": "upguard", "status_code": response.status_code},
            )
        response.raise_for_status()
        return response
