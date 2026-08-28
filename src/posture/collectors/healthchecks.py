"""Healthchecks.io collector.

Raw ``requests`` against the Healthchecks.io Management API v3
(``https://healthchecks.io/api/v3/``), no vendor SDK. Auth is a static
per-project API key sent in the ``X-Api-Key`` header — the same "just set
the credential" shape as AppOmni/Snyk/UpGuard. A **read-only** key
(``hcr_`` prefix) is enough for everything this collector reads; a
read-write key works too. There is no OAuth flow.

``api_url`` is optional config (default ``https://healthchecks.io``) for
self-hosted Healthchecks instances — the same operator-suppliable,
normalised-host shape as DNSimple's ``endpoint``.

Resources:

- ``checks`` — one row per check. ``GET /checks/`` returns every check in
  one unpaginated ``{"checks": [...]}`` envelope. Optional ``slug`` / ``tag``
  kwargs filter server-side (``tag`` repeatable). Under a read-only key the
  response carries ``unique_key`` and omits ``uuid``/``ping_url``/
  ``channels``; under a read-write key it is the other way around for the
  id. Both ``uuid`` and ``unique_key`` are declared in ``MANIFEST`` so the
  collector works with either key type.
- ``flips`` — one row per (check, status change): the recorded up/down
  history. Not ``derived_from`` ``checks`` — each check's flips are their
  own ``GET /checks/<id>/flips/`` call, fanned out across a thread pool via
  ``Collector._resumable_fanout`` (the same per-item fan-out shape as
  ``sonarcloud.py``'s per-project calls). The check id used is
  ``uuid or unique_key`` — the flips endpoint accepts either. ``_check_key``
  and ``_check_name`` are injected client-side. ``up`` is ``1`` (recovered)
  or ``0`` (went down).

  **Time-window scoped**, because the flip feed is unbounded. Bare
  ``collect("flips")`` returns the trailing 90 days. Override with exactly
  one of: ``flips_window_hours=<n>`` (synthetic, maps to the native
  ``seconds`` param), ``seconds=<n>`` (native lookback), or
  ``start``/``end`` (native UNIX-timestamp / ISO-8601 bounds — the "since
  this instant" form that lets a caller build a delta extractor). Passing
  more than one raises ``ValueError``. The ``seconds`` lookback is capped
  at 365 days server-side, so a longer window must use ``start``/``end``
  (which have no cap) — asking for more via ``flips_window_hours``/
  ``seconds`` raises ``ValueError`` rather than 400ing mid-fan-out. This is
  kwarg-driven query scoping,
  not stateful incremental sync — every run is a full point-in-time pull of
  whatever window is requested; no checkpoint is stored.

Deliberately **not** collected: ``channels`` (integrations) and ``pings``
(per-ping detail) both require a read-write key — out of reach for the
read-only key this collector targets, and out of scope for a read-only
collection library; ``badges`` (SVG/JSON badge URLs only) and ``status``
(a plain-text API liveness probe) carry no posture-relevant data.

**Live-verified** against a real project with a read-only key (2026-08-29):
``checks`` and ``flips`` (including ``unique_key`` addressing of the flips
endpoint, and the ``seconds``/``start``/``end`` window params).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, ClassVar

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger = logging.getLogger("posture.collectors.healthchecks")

_DEFAULT_API_URL = "https://healthchecks.io"
_API_PREFIX = "/api/v3"
_CHECKS_PATH = f"{_API_PREFIX}/checks/"
_DEFAULT_FLIPS_WINDOW_HOURS = 90 * 24
# The flips endpoint's `seconds` param is capped at 365 days server-side
# (a larger value 400s). Longer lookbacks must use `start`/`end`, which
# have no such cap.
_MAX_FLIPS_SECONDS = 365 * 24 * 3600
_DEFAULT_FLIPS_FANOUT_MAX_WORKERS = 10

MANIFEST: dict[str, dict[str, Any]] = {
    "checks": {
        "endpoint": _CHECKS_PATH,
        "columns": {
            "name": ("name", "str"),
            "slug": ("slug", "str"),
            "tags": ("tags", "str"),
            "desc": ("desc", "str"),
            "status": ("status", "str"),
            "grace": ("grace", "int"),
            "timeout": ("timeout", "int"),
            "schedule": ("schedule", "str"),
            "tz": ("tz", "str"),
            "n_pings": ("n_pings", "int"),
            "started": ("started", "bool"),
            "last_ping": ("last_ping", "datetime"),
            "next_ping": ("next_ping", "datetime"),
            "last_duration": ("last_duration", "int"),
            "manual_resume": ("manual_resume", "bool"),
            "methods": ("methods", "str"),
            "subject": ("subject", "str"),
            "subject_fail": ("subject_fail", "str"),
            "start_kw": ("start_kw", "str"),
            "success_kw": ("success_kw", "str"),
            "failure_kw": ("failure_kw", "str"),
            "filter_subject": ("filter_subject", "bool"),
            "filter_body": ("filter_body", "bool"),
            "filter_http_body": ("filter_http_body", "bool"),
            "filter_default_fail": ("filter_default_fail", "bool"),
            "badge_url": ("badge_url", "str"),
            "channels": ("channels", "str"),
            "uuid": ("uuid", "str"),
            "unique_key": ("unique_key", "str"),
        },
    },
    "flips": {
        # Not derived_from "checks": each check's flips are their own
        # network call, fanned out across a thread pool. requires "checks"
        # so the base class caches its raw records for the fan-out to read.
        # _check_key / _check_name are injected client-side.
        "requires": "checks",
        "endpoint": f"{_API_PREFIX}/checks/<id>/flips/",
        "columns": {
            "check_key": ("_check_key", "str"),
            "check_name": ("_check_name", "str"),
            "timestamp": ("timestamp", "datetime"),
            "up": ("up", "int"),
        },
    },
}


def _to_epoch(value: Any) -> int:
    """Coerce an epoch-seconds int/str or an ISO 8601 string to epoch seconds."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return int(value)
    text = str(value).strip()
    if text.isdigit():
        return int(text)
    dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


class HealthchecksCollector(Collector):
    env_prefix = "HEALTHCHECKS"
    display_name = "Healthchecks.io"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {"token": True, "api_url": False}
    url_config_keys: tuple[str, ...] = ("api_url",)

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        self._base_url = self._config.get("api_url", _DEFAULT_API_URL)

    def _authenticate(self) -> None:
        self._session.headers["Accept"] = "application/json"
        self._session.headers["X-Api-Key"] = self._config["token"]

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "checks":
            return self._fetch_checks_page(kwargs, cursor)
        return self._fetch_flips_fanout_page(kwargs, cursor)

    def _fetch_checks_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # /checks/ is a single unpaginated call
        params = {k: v for k, v in kwargs.items() if k in ("slug", "tag")}
        payload = self._get(self._base_url + _CHECKS_PATH, params=params).json()
        return payload.get("checks") or [], None

    def _fetch_flips_fanout_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # whole fan-out completes on the first call

        flip_params = self._flip_window_params(kwargs)

        checks = kwargs.get("check_ids")
        if checks is not None:
            targets = [(cid, None) for cid in checks]
        else:
            targets = [
                (check.get("uuid") or check.get("unique_key"), check.get("name"))
                for check in self._get_raw("checks", {})
            ]
        targets = [(cid, name) for cid, name in targets if cid]
        if not targets:
            return [], None

        max_workers = kwargs.get("max_workers", _DEFAULT_FLIPS_FANOUT_MAX_WORKERS)
        workers = max(1, min(max_workers, len(targets)))

        records = self._resumable_fanout(
            "flips",
            targets,
            lambda target: self._fetch_flips_for_check(target, flip_params),
            workers,
        )
        return records, None

    def _fetch_flips_for_check(
        self, target: tuple[str, str | None], params: dict[str, Any]
    ) -> list[dict[str, Any]]:
        check_key, check_name = target
        url = f"{self._base_url}{_API_PREFIX}/checks/{check_key}/flips/"
        payload = self._get(url, params=params).json()
        records = payload.get("flips") or []
        for record in records:
            record["_check_key"] = check_key
            record["_check_name"] = check_name
        return records

    @staticmethod
    def _flip_window_params(kwargs: dict[str, Any]) -> dict[str, Any]:
        """Resolve the flips endpoint's time-window query params from the
        caller's kwargs, defaulting to the trailing 90 days. Exactly one of
        ``flips_window_hours`` / ``seconds`` / (``start``/``end``) may be
        given."""
        window_hours = kwargs.get("flips_window_hours")
        seconds = kwargs.get("seconds")
        start = kwargs.get("start")
        end = kwargs.get("end")
        range_given = start is not None or end is not None

        if sum([window_hours is not None, seconds is not None, range_given]) > 1:
            raise ValueError(
                "pass only one of flips_window_hours, seconds, or start/end"
            )

        if range_given:
            params: dict[str, Any] = {}
            if start is not None:
                params["start"] = _to_epoch(start)
            if end is not None:
                params["end"] = _to_epoch(end)
            return params
        if seconds is not None:
            resolved = int(seconds)
        else:
            hours = (
                int(window_hours)
                if window_hours is not None
                else _DEFAULT_FLIPS_WINDOW_HOURS
            )
            resolved = hours * 3600
        if resolved > _MAX_FLIPS_SECONDS:
            raise ValueError(
                "flips lookback exceeds the endpoint's 365-day 'seconds' cap; "
                "use start/end for a longer range"
            )
        return {"seconds": resolved}

    def _get(self, url: str, params: dict[str, Any] | None = None) -> Any:
        response = self._session.get(url, params=params, timeout=30)
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitedSignal(
                retry_after=float(retry_after) if retry_after else None
            )
        if response.status_code in (401, 403):
            raise UnauthorizedSignal()
        response.raise_for_status()
        return response
