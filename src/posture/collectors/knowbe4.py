"""KnowBe4 Security Awareness Training collector.

Raw ``requests`` against the KnowBe4 API v1 — no vendor SDK. Auth, retry
(429/401/connection-error), and reporting come from the base Collector.
Pagination is KnowBe4's plain ``page``/``per_page`` scheme: keep requesting
the next page until a short page comes back.

``pst_recipients`` fans out per PST (phishing security test) id across a
thread pool — each PST's recipients are their own paginated endpoint, not
data nested inside the PST list response, so this mirrors MDE's
``machine_vulnerabilities`` per-item fan-out (see CLAUDE.md "Performance:
per-item fan-out") rather than a ``derived_from``/``record_path`` explosion.
PST ids are read from ``psts`` internally when not supplied via kwargs.

Resources: ``training_enrollments``, ``psts``, ``pst_recipients`` (requires
PST ids, fetched internally from ``psts`` when absent).
"""

from __future__ import annotations

import concurrent.futures
import logging
import os
import threading
import time
from collections import deque
from typing import Any

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger_name = "posture.knowbe4"
logger = logging.getLogger(logger_name)

_REGION_BASE_URLS = {
    "us": "https://us.api.knowbe4.com",
    "eu": "https://eu.api.knowbe4.com",
}
_DEFAULT_REGION = "us"
_PAGE_SIZE = 500

# KnowBe4's documented limits: 4 requests/second burst, 50 requests/minute
# sustained. ``pst_recipients`` fans out across a thread pool and can run for
# well over a minute across many PSTs/pages, so pacing on the 4 req/s figure
# alone isn't enough — held up for more than ~12s it blows straight through
# the 50/min sustained cap (4 req/s * 60s = 240/min), and every retry
# re-bursts the same way (the whole fan-out is redone from scratch on
# RateLimitExhausted — see base.py's all-or-nothing contract), exhausting
# retries without ever landing a record. Worker count is capped to match the
# 4 req/s ceiling; the pacing lock enforces both ceilings even under retry.
_DEFAULT_PST_RECIPIENTS_MAX_WORKERS = 4
_MIN_REQUEST_INTERVAL_SECONDS = 0.25
_MAX_REQUESTS_PER_MINUTE = 50
_RATE_WINDOW_SECONDS = 60.0

_ENDPOINTS = {
    "training_enrollments": "/v1/training/enrollments",
    "psts": "/v1/phishing/security_tests",
    "pst_recipients": "/v1/phishing/security_tests/{id}/recipients",
}

MANIFEST: dict[str, dict[str, Any]] = {
    "training_enrollments": {
        "endpoint": _ENDPOINTS["training_enrollments"],
        "columns": {
            "enrollment_id": ("enrollment_id", "int"),
            "user_id": ("user.id", "int"),
            "user_email": ("user.email", "str"),
            "user_first_name": ("user.first_name", "str"),
            "user_last_name": ("user.last_name", "str"),
            "content_type": ("content_type", "str"),
            "module_name": ("module_name", "str"),
            "campaign_name": ("campaign_name", "str"),
            "enrollment_date": ("enrollment_date", "datetime"),
            "start_date": ("start_date", "datetime"),
            "completion_date": ("completion_date", "datetime"),
            "status": ("status", "str"),
            "time_spent": ("time_spent", "int"),
        },
    },
    "psts": {
        "endpoint": _ENDPOINTS["psts"],
        "columns": {
            "pst_id": ("pst_id", "int"),
            "campaign_id": ("campaign_id", "int"),
            "name": ("name", "str"),
            "status": ("status", "str"),
            "groups": ("groups", "json"),
            "phish_prone_percentage": ("phish_prone_percentage", "float"),
            "started_at": ("started_at", "datetime"),
            "duration": ("duration", "int"),
            "categories": ("categories", "json"),
            "template_id": ("template_id", "int"),
            "landing_page_id": ("landing_page_id", "int"),
            "scheduled_count": ("scheduled_count", "int"),
            "delivered_count": ("delivered_count", "int"),
            "opened_count": ("opened_count", "int"),
            "clicked_count": ("clicked_count", "int"),
            "replied_count": ("replied_count", "int"),
            "attachment_open_count": ("attachment_open_count", "int"),
            "macro_enabled_count": ("macro_enabled_count", "int"),
            "data_entered_count": ("data_entered_count", "int"),
            "qr_code_scanned_count": ("qr_code_scanned_count", "int"),
            "reported_count": ("reported_count", "int"),
            "bounced_count": ("bounced_count", "int"),
        },
    },
    "pst_recipients": {
        # Not derived_from "psts": each PST's recipients are their own
        # paginated network call, fanned out across a thread pool, not data
        # nested inside the raw PST record. _pst_id is injected client-side
        # (see _fetch_all_recipients_for_pst).
        "endpoint": _ENDPOINTS["pst_recipients"],
        "columns": {
            "pst_id": ("_pst_id", "int"),
            "recipient_id": ("recipient_id", "int"),
            "user_id": ("user.id", "int"),
            "user_first_name": ("user.first_name", "str"),
            "user_last_name": ("user.last_name", "str"),
            "user_email": ("user.email", "str"),
            "template_name": ("template.name", "str"),
            "scheduled_at": ("scheduled_at", "datetime"),
            "delivered_at": ("delivered_at", "datetime"),
            "opened_at": ("opened_at", "datetime"),
            "clicked_at": ("clicked_at", "datetime"),
            "replied_at": ("replied_at", "datetime"),
            "attachment_opened_at": ("attachment_opened_at", "datetime"),
            "macro_enabled_at": ("macro_enabled_at", "datetime"),
            "data_entered_at": ("data_entered_at", "datetime"),
            "qr_code_scanned_at": ("qr_code_scanned_at", "datetime"),
            "reported_at": ("reported_at", "datetime"),
            "bounced_at": ("bounced_at", "datetime"),
            "ip": ("ip", "str"),
            "ip_location": ("ip_location", "str"),
            "browser": ("browser", "str"),
            "browser_version": ("browser_version", "str"),
            "os": ("os", "str"),
        },
    },
}


class Knowbe4Collector(Collector):
    env_prefix = "KNOWBE4"
    manifest = MANIFEST
    required_config_keys = ("api_token",)

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        region = (
            (config or {}).get("region")
            or os.environ.get("KNOWBE4_REGION")
            or _DEFAULT_REGION
        )
        self._base_url = _REGION_BASE_URLS.get(
            region, _REGION_BASE_URLS[_DEFAULT_REGION]
        )
        self._rate_limit_lock = threading.Lock()
        self._last_request_time = 0.0
        self._request_times: deque[float] = deque()

    def _authenticate(self) -> None:
        self._session.headers["Authorization"] = f"Bearer {self._config['api_token']}"
        self._session.headers["Accept"] = "application/json"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "pst_recipients":
            return self._fetch_pst_recipients_page(kwargs, cursor)
        return self._fetch_list_page(resource, kwargs, cursor)

    def _fetch_list_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        page = cursor if cursor is not None else 1
        endpoint = self.manifest[resource]["endpoint"]
        params: dict[str, Any] = {"page": page, "per_page": _PAGE_SIZE}
        params.update(kwargs)

        records = self._get(endpoint, params).json()
        next_cursor = page + 1 if len(records) == _PAGE_SIZE else None
        return records, next_cursor

    def _fetch_pst_recipients_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # entire fan-out already completed on first call

        pst_ids = kwargs.get("pst_ids")
        if pst_ids is None:
            raw_psts = self._get_raw("psts", {})
            pst_ids = [p["pst_id"] for p in raw_psts if p.get("pst_id") is not None]
        if not pst_ids:
            return [], None

        max_workers = kwargs.get("max_workers", _DEFAULT_PST_RECIPIENTS_MAX_WORKERS)
        workers = max(1, min(max_workers, len(pst_ids)))

        all_records: list[dict[str, Any]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(self._fetch_all_recipients_for_pst, pst_id): pst_id
                for pst_id in pst_ids
            }
            for future in concurrent.futures.as_completed(futures):
                all_records.extend(future.result())

        return all_records, None

    def _fetch_all_recipients_for_pst(self, pst_id: Any) -> list[dict[str, Any]]:
        endpoint = _ENDPOINTS["pst_recipients"].format(id=pst_id)
        records: list[dict[str, Any]] = []
        page = 1
        while True:
            params = {"page": page, "per_page": _PAGE_SIZE}
            page_records = self._get(endpoint, params).json()
            if not page_records:
                break
            for record in page_records:
                record["_pst_id"] = pst_id
            records.extend(page_records)
            if len(page_records) < _PAGE_SIZE:
                break
            page += 1
        return records

    def _pace_request(self) -> None:
        # Shared across threads so concurrent pst_recipients workers can't
        # collectively exceed either ceiling even though each thread only
        # knows about its own requests: the 4 req/s burst limit (min gap
        # since the last request) and the 50 req/min sustained limit (a
        # rolling 60s window over all request timestamps).
        with self._rate_limit_lock:
            now = time.monotonic()
            elapsed = now - self._last_request_time
            wait = _MIN_REQUEST_INTERVAL_SECONDS - elapsed

            while self._request_times and now - self._request_times[0] > _RATE_WINDOW_SECONDS:
                self._request_times.popleft()
            if len(self._request_times) >= _MAX_REQUESTS_PER_MINUTE:
                wait = max(wait, _RATE_WINDOW_SECONDS - (now - self._request_times[0]))

            if wait > 0:
                time.sleep(wait)
                now = time.monotonic()

            self._last_request_time = now
            self._request_times.append(now)

    def _get(self, endpoint: str, params: dict[str, Any]) -> Any:
        self._pace_request()
        response = self._session.get(
            self._base_url + endpoint, params=params, timeout=30
        )
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
                extra={"source": "knowbe4", "status_code": response.status_code},
            )
        response.raise_for_status()
        return response
