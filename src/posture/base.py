"""Collector ABC: config resolution, auth lifecycle, request handling,
pagination scaffold, session cache, and observability surface.

Concrete collectors (e.g. ``collectors/crowdstrike.py``) implement
``_authenticate`` and ``_fetch_page``; everything else — retry/backoff,
401-triggered re-auth, rate-limit pacing, the session cache, and report/
schema introspection — lives here so it is never reimplemented per vendor.
"""

from __future__ import annotations

import logging
import os
import random
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import pandas as pd
import requests

from posture.exceptions import (
    IncompleteCollection,
    RateLimitExhausted,
    ResourceUnknown,
)
from posture.parse import parse

logger = logging.getLogger("posture.base")

_MAX_RETRIES = 5
_BACKOFF_BASE_SECONDS = 1.0
_BACKOFF_CAP_SECONDS = 60.0

# A 429 is a "wait and try again" signal, not a terminal failure — it gets a
# much higher retry budget than auth/other errors. Not literally unbounded:
# a permanently misconfigured app registration or a genuinely broken quota
# must still surface as RateLimitExhausted eventually rather than spinning
# the process forever. Backoff still caps at _BACKOFF_CAP_SECONDS per attempt.
_MAX_RATE_LIMIT_RETRIES = 100

_MAX_CONNECTION_RETRIES = 2
_CONNECTION_RETRY_WAIT_SECONDS = 5.0

# Collectors that fan out per-item network calls (e.g. one detail request per
# id) share this session, so the connection pool must be sized to match —
# otherwise urllib3 logs "Connection pool is full" and serialises anyway.
# Must stay >= the largest fan-out worker count across collectors (MDE's
# machine_vulnerabilities defaults to 25 workers).
_HTTP_POOL_MAXSIZE = 32
_TRANSIENT_CONNECTION_ERRORS = (
    requests.exceptions.ConnectionError,
    requests.exceptions.Timeout,
    requests.exceptions.ChunkedEncodingError,
)


@dataclass
class _CollectionReport:
    resource: str
    pages: int = 0
    records: int = 0
    retries: int = 0
    rate_limited_count: int = 0
    coercion_warnings: int = 0
    duration_seconds: float = 0.0
    collected_at: datetime | None = None


@dataclass
class _CacheEntry:
    raw_records: list[dict[str, Any]]
    report: _CollectionReport


class Collector(ABC):
    """Base class for a single authenticated session against one source.

    One instance = one point-in-time snapshot of one tenant. Multi-tenant
    collection means constructing a second instance.
    """

    #: Env var prefix used for config resolution, e.g. "CROWDSTRIKE".
    env_prefix: str = ""

    #: Human-readable source name for catalog()/reporting, e.g.
    #: "Microsoft Defender for Endpoint" for the "mde" source. Falls back to
    #: env_prefix when a collector doesn't set it, so this is opt-in.
    display_name: str = ""

    #: resource name -> manifest dict (see parse.py for manifest shape).
    manifest: dict[str, dict[str, Any]] = {}

    #: Required config keys, resolved from constructor dict or env vars.
    required_config_keys: tuple[str, ...] = ()

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        *,
        record_limit: int | None = None,
    ) -> None:
        self._config = self._resolve_config(config or {})
        self._session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_maxsize=_HTTP_POOL_MAXSIZE)
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)
        self._authenticated = False
        self._cache: dict[tuple[str, tuple], _CacheEntry] = {}
        self._reports: dict[str, _CollectionReport] = {}
        #: Caps raw records per resource, for a quick smoke test instead of a
        #: full collection run. Truncates after whichever page crosses the
        #: limit rather than requesting an exact count — a page or two of
        #: over-fetch is a non-issue next to the runtime this is meant to
        #: avoid. Fan-out resources (e.g. Intune's managed_device_detail)
        #: inherit the cap for free: their per-id requests are driven by
        #: their source resource's raw records, which are already truncated.
        self._record_limit = record_limit

    def _resolve_config(self, explicit: dict[str, Any]) -> dict[str, Any]:
        resolved: dict[str, Any] = {}
        for key in self.required_config_keys:
            if key in explicit:
                resolved[key] = explicit[key]
                continue
            env_var = f"{self.env_prefix}_{key.upper()}"
            value = os.environ.get(env_var)
            if value is None:
                raise ValueError(
                    f"Missing required config '{key}': set it explicitly or via "
                    f"env var {env_var}"
                )
            resolved[key] = value
        return resolved

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(config=<redacted>)"

    def collect(self, resource: str, **kwargs: Any) -> pd.DataFrame:
        """Return a complete DataFrame for ``resource``, always.

        All-or-nothing: if collection dies mid-pagination after retries are
        exhausted, raises IncompleteCollection rather than returning a
        partial snapshot.
        """
        manifest = self.manifest.get(resource)
        if manifest is None:
            raise ResourceUnknown(
                f"Unknown resource '{resource}' for {self.__class__.__name__}",
                source=self.env_prefix.lower(),
                resource=resource,
            )

        derived_from = manifest.get("derived_from")
        source_resource = derived_from if derived_from is not None else resource
        raw_records = self._get_raw(source_resource, kwargs)
        self._reports[resource] = self._reports[source_resource]

        df = parse(raw_records, manifest, resource=resource)
        df["_collected_at"] = pd.Timestamp(datetime.now(timezone.utc))
        return df

    def _get_raw(self, resource: str, kwargs: dict[str, Any]) -> list[dict[str, Any]]:
        cache_key = (resource, tuple(sorted(kwargs.items())))
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached.raw_records

        raw_records, report = self._collect_raw(resource, kwargs)

        # Two distinct relationships justify caching: "derived_from" (a
        # parse-time relationship — another resource's rows are exploded out
        # of this one's raw records, e.g. vulnerability_remediations out of
        # vulnerabilities) and "requires" (a collect-time relationship — a
        # collector needs this resource's raw records again internally, e.g.
        # MDE's machine_vulnerabilities re-reading machines' ids for its
        # fan-out). Neither implies the other: a "requires" consumer fetches
        # its own records over the network rather than exploding this
        # resource's raw records, so it must not be parsed via derived_from's
        # record_path/$parent. machinery.
        is_reused = any(
            m.get("derived_from") == resource or m.get("requires") == resource
            for m in self.manifest.values()
        )
        if is_reused:
            self._cache[cache_key] = _CacheEntry(raw_records, report)
        self._reports[resource] = report
        return raw_records

    def _collect_raw(
        self, resource: str, kwargs: dict[str, Any]
    ) -> tuple[list[dict[str, Any]], _CollectionReport]:
        self._ensure_authenticated()

        report = _CollectionReport(resource=resource)
        started = time.monotonic()
        records: list[dict[str, Any]] = []

        try:
            for page in self._paginate(resource, kwargs, report):
                records.extend(page)
                report.pages += 1
                report.records = len(records)
                logger.debug(
                    "fetched page",
                    extra={
                        "source": self.env_prefix.lower(),
                        "resource": resource,
                        "page": report.pages,
                        "records": report.records,
                    },
                )
                if (
                    self._record_limit is not None
                    and len(records) >= self._record_limit
                ):
                    records = records[: self._record_limit]
                    report.records = len(records)
                    break
        except IncompleteCollection:
            raise
        except Exception as exc:  # noqa: BLE001 - convert to domain exception
            raise IncompleteCollection(
                f"Collection of '{resource}' failed after {len(records)} records: {exc}",
                source=self.env_prefix.lower(),
                resource=resource,
                records_so_far=len(records),
            ) from exc

        report.duration_seconds = time.monotonic() - started
        report.collected_at = datetime.now(timezone.utc)
        return records, report

    def _paginate(
        self, resource: str, kwargs: dict[str, Any], report: _CollectionReport
    ):
        cursor = None
        while True:
            page, cursor = self._request_with_retry(resource, kwargs, cursor, report)
            yield page
            if cursor is None:
                return

    def _request_with_retry(
        self,
        resource: str,
        kwargs: dict[str, Any],
        cursor: Any,
        report: _CollectionReport,
    ) -> tuple[list[dict[str, Any]], Any]:
        attempt = 0
        rate_limit_attempt = 0
        connection_attempt = 0
        while True:
            try:
                return self._fetch_page(resource, kwargs, cursor)
            except RateLimitedSignal as exc:
                report.rate_limited_count += 1
                rate_limit_attempt += 1
                if rate_limit_attempt > _MAX_RATE_LIMIT_RETRIES:
                    raise RateLimitExhausted(
                        f"Rate limit retries exhausted for '{resource}'",
                        source=self.env_prefix.lower(),
                        resource=resource,
                        records_so_far=report.records,
                    ) from exc
                report.retries += 1
                wait = min(
                    exc.retry_after or _BACKOFF_BASE_SECONDS * (2**rate_limit_attempt),
                    _BACKOFF_CAP_SECONDS,
                )
                # Jitter (+/-25%) so concurrent collector runs against the same
                # rate-limited source (e.g. several tenants dispatched in parallel
                # by cron.py, or a fan-out retry racing other resources) don't all
                # wake up and re-hit the API at the exact same moment.
                time.sleep(wait * random.uniform(0.75, 1.25))
            except UnauthorizedSignal:
                attempt += 1
                if attempt > _MAX_RETRIES:
                    raise
                report.retries += 1
                self._authenticated = False
                self._ensure_authenticated()
            except _TRANSIENT_CONNECTION_ERRORS as exc:
                connection_attempt += 1
                if connection_attempt > _MAX_CONNECTION_RETRIES:
                    raise
                report.retries += 1
                logger.warning(
                    "transient connection error, retrying",
                    extra={
                        "source": self.env_prefix.lower(),
                        "resource": resource,
                        "attempt": connection_attempt,
                        "error": str(exc),
                    },
                )
                time.sleep(_CONNECTION_RETRY_WAIT_SECONDS)

    def _ensure_authenticated(self) -> None:
        if not self._authenticated:
            self._authenticate()
            self._authenticated = True
            logger.debug("authenticated", extra={"source": self.env_prefix.lower()})

    @abstractmethod
    def _authenticate(self) -> None:
        """Perform auth against the source, populating self._session headers."""

    @abstractmethod
    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        """Fetch one page. Return (records, next_cursor); next_cursor=None ends pagination."""

    def report(self, resource: str) -> dict[str, Any]:
        rep = self._reports.get(resource)
        if rep is None:
            raise ResourceUnknown(
                f"No report available for '{resource}' — collect() it first",
                source=self.env_prefix.lower(),
                resource=resource,
            )
        return {
            "resource": rep.resource,
            "pages": rep.pages,
            "records": rep.records,
            "retries": rep.retries,
            "rate_limited_count": rep.rate_limited_count,
            "coercion_warnings": rep.coercion_warnings,
            "duration_seconds": rep.duration_seconds,
            "collected_at": rep.collected_at,
        }

    def tables(self) -> list[str]:
        """Return the resource names this collector's manifest declares."""
        return list(self.manifest.keys())

    def schema(self, resource: str) -> dict[str, Any]:
        manifest = self.manifest.get(resource)
        if manifest is None:
            raise ResourceUnknown(
                f"Unknown resource '{resource}' for {self.__class__.__name__}",
                source=self.env_prefix.lower(),
                resource=resource,
            )
        return manifest

    def flush_cache(self) -> None:
        self._cache.clear()


class RateLimitedSignal(Exception):
    def __init__(self, retry_after: float | None = None) -> None:
        super().__init__("rate limited")
        self.retry_after = retry_after


class UnauthorizedSignal(Exception):
    pass
