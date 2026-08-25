"""Collector ABC: config resolution, auth lifecycle, request handling,
pagination scaffold, session cache, and observability surface.

Concrete collectors (e.g. ``collectors/crowdstrike.py``) implement
``_authenticate`` and ``_fetch_page``; everything else — retry/backoff,
401-triggered re-auth, rate-limit pacing, the session cache, and report/
schema introspection — lives here so it is never reimplemented per vendor.
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import os
import random
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, ClassVar

import pandas as pd
import requests

from posture._spill import SpillStore
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

_MAX_CONNECTION_RETRIES = 5
_CONNECTION_RETRY_WAIT_SECONDS = 5.0

# Collectors that fan out per-item network calls (e.g. one detail request per
# id) share this session, so the connection pool must be sized to match —
# otherwise urllib3 logs "Connection pool is full" and serialises anyway.
# Must stay >= the largest fan-out worker count across collectors (MDE's
# machine_vulnerabilities defaults to 25 workers).
_HTTP_POOL_MAXSIZE = 32

# Refresh a token this many seconds before it actually expires, so a request
# already in flight doesn't race the token dying mid-call.
_TOKEN_REFRESH_MARGIN_SECONDS = 300

_TRANSIENT_CONNECTION_ERRORS = (
    requests.exceptions.ConnectionError,
    requests.exceptions.Timeout,
    requests.exceptions.ChunkedEncodingError,
)


def _freeze(value: Any) -> Any:
    """Recursively convert a kwarg value into something hashable, for use in
    _iter_raw_pages' page-cache key. A collector's kwargs are the vendor
    query dialect (e.g. a list-valued `types`/`device_ids`/`products` kwarg)
    and are never restricted to hashable types by the locked kwargs contract
    — only this cache key's own tuple() needs every value hashable, so that
    requirement is handled here rather than pushed onto every collector.
    Dict key order doesn't affect the resulting key: keys are sorted before
    freezing, same as the top-level kwargs.items() sort this feeds into.
    """
    if isinstance(value, dict):
        return tuple(sorted((k, _freeze(v)) for k, v in value.items()))
    if isinstance(value, (list, tuple, set)):
        return tuple(_freeze(v) for v in value)
    return value


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
    # Raw records live on disk (see posture._spill), not in this dataclass —
    # only the spill file's path is kept resident for the collector's
    # lifetime; the records themselves are read back into memory only while
    # actually being consumed.
    path: Path
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
    manifest: ClassVar[dict[str, dict[str, Any]]] = {}

    #: Every config key the collector accepts, mapped to whether it's
    #: required. Each is resolved from the constructor dict, else the env
    #: var f"{env_prefix}_{key.upper()}", else (for a key mapped to False)
    #: left unset — collection still succeeds and the collector's own
    #: __init__ applies its default. A required key missing everywhere
    #: raises ValueError. This is also catalog()'s only source for
    #: documenting a collector's config surface, so a key resolved via a
    #: raw os.environ.get(...) instead of being listed here is invisible to
    #: catalog() and the generated docs — don't do that.
    config_keys: ClassVar[dict[str, bool]] = {}

    #: Subset of config_keys holding a base URL/endpoint. Operators
    #: routinely supply these with or without a scheme ("host.example.com"
    #: vs "https://host.example.com") depending on the vendor's own docs —
    #: normalized here so every collector accepts either and ends up with
    #: exactly one shape (explicit https://, no trailing slash) rather than
    #: each collector guessing at request time.
    url_config_keys: tuple[str, ...] = ()

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
        self._authenticated = False
        #: When set by a concrete collector's _authenticate() (e.g. Azure AD
        #: collectors, which know their token's expires_in), enables proactive
        #: refresh in _ensure_authenticated() ahead of expiry. Optional: a
        #: collector that never sets it just keeps the existing
        #: authenticate-once-per-run behaviour.
        self._token_expires_at: datetime | None = None
        self._spill = SpillStore()
        self._cache: dict[tuple[str, tuple], _CacheEntry] = {}
        self._reports: dict[str, _CollectionReport] = {}
        #: Per-resource progress for _resumable_fanout(), keyed by resource,
        #: value is {item_id: fetch_one(item_id) result}. Survives a
        #: _fetch_page retry within the same fan-out (see _resumable_fanout);
        #: cleared on that fan-out's success.
        self._fanout_progress: dict[str, dict[Any, Any]] = {}
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
        for key, required in self.config_keys.items():
            if key in explicit:
                resolved[key] = explicit[key]
                continue
            env_var = f"{self.env_prefix}_{key.upper()}"
            value = os.environ.get(env_var)
            if value is None:
                if required:
                    raise ValueError(
                        f"Missing required config '{key}': set it explicitly or "
                        f"via env var {env_var}"
                    )
                continue
            resolved[key] = value
        for key in self.url_config_keys:
            if key in resolved:
                resolved[key] = self._normalize_url(resolved[key])
        return resolved

    @staticmethod
    def _normalize_url(value: str) -> str:
        """Ensure a base URL/endpoint has an explicit https:// scheme, no trailing slash.

        Operators may supply a bare host ("host.example.com"), a full URL
        ("https://host.example.com/"), or even an explicit "http://" —
        all normalize to https://.
        """
        value = value.strip()
        value = value.removeprefix("http://")
        if not value.startswith("https://"):
            value = f"https://{value}"
        return value.rstrip("/")

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(config=<redacted>)"

    def collect(self, resource: str, **kwargs: Any) -> pd.DataFrame:
        """Return a complete DataFrame for ``resource``, always.

        A thin wrapper over collect_page(): runs the full pagination and
        concatenates every page's DataFrame. All-or-nothing: if collection
        dies mid-pagination after retries are exhausted, collect_page raises
        IncompleteCollection before this returns anything — no partial
        snapshot is ever handed back.

        For a resource too large to hold comfortably in memory as a single
        DataFrame, use collect_page() directly and process one page at a time.
        """
        pages = list(self.collect_page(resource, **kwargs))
        if not pages:
            manifest = self.schema(resource)
            df = pd.DataFrame(columns=list(manifest["columns"].keys()))
            df["_collected_at"] = pd.Timestamp(datetime.now(timezone.utc))
            return df
        return pd.concat(pages, ignore_index=True)

    def collect_page(self, resource: str, **kwargs: Any) -> Iterator[pd.DataFrame]:
        """Yield one parsed DataFrame per underlying API page for ``resource``.

        Bounds peak memory to a single page rather than the whole resource —
        pages are parsed and yielded as they're fetched, never accumulated.
        All-or-nothing still holds: if collection fails mid-pagination, the
        exception raised here (IncompleteCollection) propagates out of the
        loop the caller is iterating, same as any other generator failure —
        it's the caller's job to treat a raised exception as "nothing valid
        was produced", exactly as collect() does by wrapping this in list().
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
        for raw_page in self._iter_raw_pages(source_resource, kwargs):
            df = parse(raw_page, manifest, resource=resource)
            df["_collected_at"] = pd.Timestamp(datetime.now(timezone.utc))
            yield df
        self._reports[resource] = self._reports[source_resource]

    def _get_raw(self, resource: str, kwargs: dict[str, Any]) -> list[dict[str, Any]]:
        """Materialize a resource's raw records as one list.

        For internal collector use only (a collector's own fan-out logic
        needing another resource's ids/records again, e.g. an org list
        driving per-org detail calls via manifest 'requires') — never for the
        main collect path, which stays page-bounded via collect_page(). Only
        safe for resources small enough to hold in memory at once; the
        resources this is called on today (org/zone/vendor lists, etc.) are.
        """
        raw_records: list[dict[str, Any]] = []
        for page in self._iter_raw_pages(resource, kwargs):
            raw_records.extend(page)
        return raw_records

    def _resumable_fanout(
        self,
        resource: str,
        ids: list[Any],
        fetch_one: Callable[[Any], Any],
        max_workers: int,
    ) -> list[dict[str, Any]]:
        """Fan ``fetch_one`` out across ``ids`` on a thread pool, persisting
        partial progress across retries of the same ``_fetch_page`` call.

        A per-item fan-out (e.g. one detail request per id) that models the
        whole id list as a single page has no cursor to resume from — a mid-
        run failure (token expiry, a transient connection error) makes
        ``_request_with_retry`` re-call ``_fetch_page`` from scratch. Without
        this, every already-completed id would be re-fetched. Progress is
        recorded into ``self._fanout_progress[resource]`` as each future
        completes, not batched into a local list only assembled at the end,
        so a mid-run exception leaves the completed work intact for the next
        attempt to resume from; only ids missing from progress are resubmitted.

        Cleared on success so state doesn't leak into a later, unrelated call
        for the same resource. Safe without locking: ``collect_page`` drives
        ``_paginate`` serially, so ``_fetch_page`` is never called
        concurrently for the same resource on the same collector instance.

        ``fetch_one`` may return a single record, ``None`` (e.g. a 404 the
        caller treats as "confirmed missing" — still a completed result, not
        re-fetched on retry), or a list of records (e.g. an id whose own
        fetch is itself paginated). Returned records are flattened
        accordingly; ``None`` results are dropped.
        """
        progress = self._fanout_progress.setdefault(resource, {})
        remaining_ids = [item_id for item_id in ids if item_id not in progress]
        if remaining_ids:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_workers
            ) as executor:
                futures = {
                    executor.submit(fetch_one, item_id): item_id
                    for item_id in remaining_ids
                }
                try:
                    for future in concurrent.futures.as_completed(futures):
                        item_id = futures[future]
                        progress[item_id] = future.result()
                except BaseException:
                    # A worker failed (e.g. token expired mid-run, raising
                    # UnauthorizedSignal). Cancel every future that hasn't
                    # started yet so the pool doesn't keep burning through the
                    # remaining queue against a dead token before __exit__'s
                    # shutdown(wait=True) can return control to
                    # _request_with_retry. progress already has every result
                    # completed before this point.
                    for pending in futures:
                        pending.cancel()
                    raise

        records: list[dict[str, Any]] = []
        for result in progress.values():
            if result is None:
                continue
            if isinstance(result, list):
                records.extend(result)
            else:
                records.append(result)
        del self._fanout_progress[resource]
        return records

    def _iter_raw_pages(
        self, resource: str, kwargs: dict[str, Any]
    ) -> Iterator[list[dict[str, Any]]]:
        cache_key = (
            resource,
            tuple(sorted((k, _freeze(v)) for k, v in kwargs.items())),
        )
        cached = self._cache.get(cache_key)
        if cached is not None:
            yield from self._spill.read_pages(cached.path)
            return

        # Two distinct relationships justify caching to disk: "derived_from"
        # (a parse-time relationship — another resource's rows are exploded
        # out of this one's raw records, e.g. vulnerability_remediations out
        # of vulnerabilities) and "requires" (a collect-time relationship — a
        # collector needs this resource's raw records again internally, e.g.
        # MDE's machine_vulnerabilities re-reading machines' ids for its
        # fan-out). Neither implies the other: a "requires" consumer fetches
        # its own records over the network rather than exploding this
        # resource's raw records, so it must not be parsed via derived_from's
        # record_path/$parent machinery. A resource nobody reuses is never
        # written to disk at all — it streams straight from fetch to parse.
        is_reused = any(
            m.get("derived_from") == resource or m.get("requires") == resource
            for m in self.manifest.values()
        )
        self._ensure_authenticated_with_retry(resource)

        report = _CollectionReport(resource=resource)
        started = time.monotonic()
        count = 0
        path = self._spill.new_path(resource) if is_reused else None
        fh = path.open("w", encoding="utf-8") if path is not None else None
        # next(paginator) is wrapped in try/except so only fetch/pagination
        # failures become IncompleteCollection; `yield page` below is
        # deliberately outside that try — an exception a consumer raises
        # while processing a yielded page (e.g. a parse() error downstream)
        # resumes *here* at the yield point, and must propagate as itself,
        # not get relabelled as a failed collection.
        paginator = self._paginate(resource, kwargs, report)
        try:
            while True:
                try:
                    page = next(paginator)
                except StopIteration:
                    break
                except IncompleteCollection:
                    raise
                except Exception as exc:
                    raise IncompleteCollection(
                        f"Collection of '{resource}' failed after {count} records: {exc}",
                        source=self.env_prefix.lower(),
                        resource=resource,
                        records_so_far=count,
                    ) from exc

                if self._record_limit is not None:
                    remaining = self._record_limit - count
                    if remaining <= 0:
                        break
                    if len(page) > remaining:
                        page = page[:remaining]
                if fh is not None:
                    for record in page:
                        fh.write(json.dumps(record))
                        fh.write("\n")
                count += len(page)
                report.pages += 1
                report.records = count
                logger.debug(
                    "fetched page",
                    extra={
                        "source": self.env_prefix.lower(),
                        "resource": resource,
                        "page": report.pages,
                        "records": report.records,
                    },
                )
                yield page
                if self._record_limit is not None and count >= self._record_limit:
                    break
        except Exception:
            # Close before delete: on Windows, unlinking a still-open file
            # handle raises PermissionError (unlike POSIX, where the inode
            # persists until close) — fh must be closed first, not in the
            # finally block below, which runs after this except clause.
            if fh is not None:
                fh.close()
                fh = None
            if path is not None:
                self._spill.delete(path)
            raise
        finally:
            if fh is not None:
                fh.close()

        report.duration_seconds = time.monotonic() - started
        report.collected_at = datetime.now(timezone.utc)
        self._reports[resource] = report
        if path is not None:
            # Kept on disk for later reuse rather than in memory: the path
            # lives in self._cache for the collector's lifetime, but the
            # records themselves are only ever materialized transiently, in
            # replay batches. Cleaned up by flush_cache()/process exit.
            self._cache[cache_key] = _CacheEntry(path, report)

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
                self._ensure_authenticated_with_retry(resource)
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
                self._ensure_authenticated_with_retry(resource)
            except PermissionDeniedSignal:
                # A genuine 403, not an expired token — re-authenticating and
                # retrying can't fix a permissions problem, so fail fast
                # with the detail intact rather than burning _MAX_RETRIES
                # attempts before surfacing an unhelpful error.
                raise
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
        near_expiry = self._token_expires_at is not None and datetime.now(
            timezone.utc
        ) >= self._token_expires_at - timedelta(seconds=_TOKEN_REFRESH_MARGIN_SECONDS)
        if not self._authenticated or near_expiry:
            self._authenticate()
            self._authenticated = True
            logger.debug("authenticated", extra={"source": self.env_prefix.lower()})

    def _ensure_authenticated_with_retry(self, resource: str) -> None:
        """Like ``_ensure_authenticated``, but retries transient connection
        errors/timeouts (e.g. a slow token endpoint) the same way fetch
        requests do. Deliberately outside ``_request_with_retry``'s try/except
        so that a permanent auth failure (e.g. AuthenticationError on bad
        credentials) still propagates raw rather than being relabelled as
        IncompleteCollection."""
        connection_attempt = 0
        while True:
            try:
                self._ensure_authenticated()
                return
            except _TRANSIENT_CONNECTION_ERRORS as exc:
                connection_attempt += 1
                if connection_attempt > _MAX_CONNECTION_RETRIES:
                    raise
                logger.warning(
                    "transient connection error during authentication, retrying",
                    extra={
                        "source": self.env_prefix.lower(),
                        "resource": resource,
                        "attempt": connection_attempt,
                        "error": str(exc),
                    },
                )
                time.sleep(_CONNECTION_RETRY_WAIT_SECONDS)

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
        for entry in self._cache.values():
            self._spill.delete(entry.path)
        self._cache.clear()


class RateLimitedSignal(Exception):
    def __init__(self, retry_after: float | None = None) -> None:
        super().__init__("rate limited")
        self.retry_after = retry_after


class UnauthorizedSignal(Exception):
    pass


class PermissionDeniedSignal(Exception):
    """Raised for a 403 the caller has determined is a genuine permissions
    failure, not an expired token — retrying it won't help, unlike
    UnauthorizedSignal's 401. Carries the response detail so it survives
    into the IncompleteCollection message unembellished."""
