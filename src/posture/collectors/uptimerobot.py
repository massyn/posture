"""UptimeRobot collector.

Raw ``requests`` against UptimeRobot's API v2
(``https://api.uptimerobot.com/v2/<method>``), no vendor SDK. Every method
is an HTTP ``POST`` with an ``application/x-www-form-urlencoded`` body; the
API key travels as an ``api_key`` body field (not a header), alongside
``format=json``. A failed call still returns HTTP ``200`` with
``{"stat": "fail", "error": {...}}`` in the body, so ``_post`` inspects
``stat`` rather than trusting the status code — an ``api_key`` rejection
becomes ``UnauthorizedSignal``, the same "just set the credential" failure
shape as AppOmni/Snyk/runZero.

The API key is a single account-wide value issued in the UptimeRobot
dashboard (Settings > API). A *main* API key (prefix ``u``) grants
read + write; a *read-only* key (prefix ``ur``) is preferred for posture
and works identically here. There is no OAuth flow and no tenant host —
one fixed base URL for every account.

Resources:

- ``monitors`` — one row per monitor (config + health rollups). The
  ``getMonitors`` call requests ``custom_uptime_ratios=1-7-30-90`` and
  ``all_time_uptime_ratio``, and a single ``response_times`` sample purely
  so ``average_response_time`` is populated. UptimeRobot returns the custom
  ratios as a single dash-joined string (``"97.874-99.696-99.929-99.976"``)
  plus a parallel ``custom_down_durations`` string; ``_reshape_monitor``
  splits both into ``uptime_ratio_<n>d`` / ``down_duration_<n>d`` columns
  at fetch time (the "transform before parse.py ever sees it" shape
  ``qualys.py``/``cortex_cloud.py`` use).
- ``monitor_logs`` — one row per (monitor, event), exploded from each
  monitor's ``logs`` array on the same ``getMonitors`` call. **Scoped to a
  time window, because the log feed is noisy and unbounded.** Bare
  ``collect("monitor_logs")`` returns the trailing 48 hours. Override with
  either ``logs_window_hours=<n>`` (trailing N hours) or
  ``logs_start_date=<epoch|ISO8601>`` (everything since that instant, with
  an optional ``logs_end_date``) — the latter lets a caller build a
  delta/incremental-style extractor. The two are mutually exclusive.
  UptimeRobot caps a single ``logs_start_date``/``logs_end_date`` span at
  45 days.
- ``monitor_response_times`` — one row per (monitor, sample), exploded from
  each monitor's ``response_times`` array. ``response_times_limit`` /
  ``response_times_start_date`` / ``response_times_end_date`` pass straight
  through as kwargs. Free-plan accounts retain only a short recent window
  of response-time history.
- ``account`` — one row, from ``getAccountDetails``.
- ``alert_contacts`` — one row per configured notification destination,
  from ``getAlertContacts``.

Integer ``type`` / ``status`` fields are left as the vendor's raw codes
(allowlist, not normalisation — interpretation is the downstream SQL
layer's job). For reference: monitor ``type`` 1=HTTP(s) 2=keyword 3=ping
4=port 5=heartbeat; monitor ``status`` 0=paused 1=not-checked-yet 2=up
8=seems-down 9=down; log ``type`` 1=down 2=up 98=started 99=paused; alert
contact ``status`` 0=not-activated 1=paused 2=active.

**Live-verified** against a real account (2026-08-29): all five resources'
response envelopes, field names, and the ``stat: fail`` error shape.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, ClassVar

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger = logging.getLogger("posture.collectors.uptimerobot")

_BASE_URL = "https://api.uptimerobot.com/v2"
_MONITORS_PAGE_SIZE = 50  # API hard cap
_CONTACTS_PAGE_SIZE = 50
_RATIO_WINDOWS = (1, 7, 30, 90)
_CUSTOM_UPTIME_RATIOS = "-".join(str(w) for w in _RATIO_WINDOWS)
_DEFAULT_LOGS_WINDOW_HOURS = 48

_MONITOR_COLUMNS: dict[str, tuple] = {
    "id": ("id", "str"),
    "friendly_name": ("friendly_name", "str"),
    "url": ("url", "str"),
    "type": ("type", "int"),
    "sub_type": ("sub_type", "str"),
    "keyword_type": ("keyword_type", "int"),
    "keyword_value": ("keyword_value", "str"),
    "port": ("port", "str"),
    "interval": ("interval", "int"),
    "timeout": ("timeout", "int"),
    "status": ("status", "int"),
    "create_datetime": ("create_datetime", "datetime"),
    "average_response_time": ("average_response_time", "float"),
    "all_time_uptime_ratio": ("all_time_uptime_ratio", "float"),
    **{f"uptime_ratio_{w}d": (f"uptime_ratio_{w}d", "float") for w in _RATIO_WINDOWS},
    **{f"down_duration_{w}d": (f"down_duration_{w}d", "int") for w in _RATIO_WINDOWS},
}

MANIFEST: dict[str, dict[str, Any]] = {
    "monitors": {
        "endpoint": "getMonitors",
        "columns": _MONITOR_COLUMNS,
    },
    "monitor_logs": {
        "endpoint": "getMonitors",
        "columns": {
            "monitor_id": ("monitor_id", "str"),
            "monitor_friendly_name": ("monitor_friendly_name", "str"),
            "type": ("type", "int"),
            "datetime": ("datetime", "datetime"),
            "duration": ("duration", "int"),
            "reason_code": ("reason.code", "str"),
            "reason_detail": ("reason.detail", "str"),
        },
    },
    "monitor_response_times": {
        "endpoint": "getMonitors",
        "columns": {
            "monitor_id": ("monitor_id", "str"),
            "monitor_friendly_name": ("monitor_friendly_name", "str"),
            "datetime": ("datetime", "datetime"),
            "response_time_ms": ("value", "int"),
        },
    },
    "account": {
        "endpoint": "getAccountDetails",
        "columns": {
            "email": ("email", "str"),
            "user_id": ("user_id", "str"),
            "firstname": ("firstname", "str"),
            "sms_credits": ("sms_credits", "int"),
            "payment_period": ("payment_period", "str"),
            "subscription_expiry_date": ("subscription_expiry_date", "datetime"),
            "monitor_limit": ("monitor_limit", "int"),
            "monitor_interval": ("monitor_interval", "int"),
            "up_monitors": ("up_monitors", "int"),
            "down_monitors": ("down_monitors", "int"),
            "paused_monitors": ("paused_monitors", "int"),
            "total_monitors_count": ("total_monitors_count", "int"),
            "active_subscription": ("active_subscription", "str"),
            "registered_at": ("registered_at", "datetime"),
        },
    },
    "alert_contacts": {
        "endpoint": "getAlertContacts",
        "columns": {
            "id": ("id", "str"),
            "friendly_name": ("friendly_name", "str"),
            "type": ("type", "int"),
            "status": ("status", "int"),
            "value": ("value", "str"),
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


def _reshape_monitor(monitor: dict[str, Any]) -> dict[str, Any]:
    """Split UptimeRobot's dash-joined custom-ratio strings into per-window
    fields so parse.py's allowlist can pluck them as ordinary columns."""
    ratios = str(monitor.get("custom_uptime_ratio") or "").split("-")
    downs = str(monitor.get("custom_down_durations") or "").split("-")
    for index, window in enumerate(_RATIO_WINDOWS):
        ratio = ratios[index] if index < len(ratios) else ""
        down = downs[index] if index < len(downs) else ""
        monitor[f"uptime_ratio_{window}d"] = ratio or None
        monitor[f"down_duration_{window}d"] = down or None
    return monitor


class UptimeRobotCollector(Collector):
    env_prefix = "UPTIME_ROBOT"
    display_name = "UptimeRobot"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {"token": True}

    def _authenticate(self) -> None:
        # The API key is a per-request body field, so there is no session
        # state to establish — a bad key surfaces as UnauthorizedSignal on
        # the first real call (see _post).
        self._session.headers["Accept"] = "application/json"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "account":
            account = self._post("getAccountDetails", {}).get("account") or {}
            return [account] if account else [], None
        if resource == "alert_contacts":
            return self._fetch_alert_contacts_page(cursor)
        return self._fetch_monitors_page(resource, dict(kwargs), cursor)

    def _fetch_monitors_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        offset = int(cursor) if cursor is not None else 0
        params: dict[str, Any] = {"offset": offset, "limit": _MONITORS_PAGE_SIZE}

        if resource == "monitors":
            params["custom_uptime_ratios"] = _CUSTOM_UPTIME_RATIOS
            params["all_time_uptime_ratio"] = 1
            params["response_times"] = 1
            params["response_times_limit"] = 1
        elif resource == "monitor_logs":
            start, end = self._log_window(kwargs)
            params["logs"] = 1
            params["logs_start_date"] = start
            params["logs_end_date"] = end
        elif resource == "monitor_response_times":
            params["response_times"] = 1

        params.update(kwargs)
        payload = self._post("getMonitors", params)
        monitors = payload.get("monitors") or []

        if resource == "monitors":
            records: list[dict[str, Any]] = [_reshape_monitor(m) for m in monitors]
        elif resource == "monitor_logs":
            records = [
                {
                    "monitor_id": m.get("id"),
                    "monitor_friendly_name": m.get("friendly_name"),
                    **log,
                }
                for m in monitors
                for log in (m.get("logs") or [])
            ]
        else:  # monitor_response_times
            records = [
                {
                    "monitor_id": m.get("id"),
                    "monitor_friendly_name": m.get("friendly_name"),
                    "datetime": sample.get("datetime"),
                    "value": sample.get("value"),
                }
                for m in monitors
                for sample in (m.get("response_times") or [])
            ]

        pagination = payload.get("pagination") or {}
        total = int(pagination.get("total", len(monitors)))
        next_offset = offset + _MONITORS_PAGE_SIZE
        return records, (next_offset if next_offset < total else None)

    def _fetch_alert_contacts_page(
        self, cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        offset = int(cursor) if cursor is not None else 0
        payload = self._post(
            "getAlertContacts", {"offset": offset, "limit": _CONTACTS_PAGE_SIZE}
        )
        records = payload.get("alert_contacts") or []
        total = int(payload.get("total", len(records)))
        next_offset = offset + _CONTACTS_PAGE_SIZE
        return records, (next_offset if next_offset < total else None)

    def _log_window(self, kwargs: dict[str, Any]) -> tuple[int, int]:
        """Resolve (logs_start_date, logs_end_date) as epoch seconds from the
        caller's kwargs, defaulting to the trailing 48 hours. ``kwargs`` is
        mutated in place: the synthetic ``logs_window_hours`` knob is popped
        so it is never sent to UptimeRobot, while an explicit
        ``logs_start_date``/``logs_end_date`` is normalised and left for
        ``params.update(kwargs)`` to apply."""
        window_hours = kwargs.pop("logs_window_hours", None)
        if window_hours is not None and "logs_start_date" in kwargs:
            raise ValueError(
                "pass either logs_window_hours or logs_start_date, not both"
            )

        now = int(time.time())
        end = _to_epoch(kwargs["logs_end_date"]) if "logs_end_date" in kwargs else now
        if "logs_start_date" in kwargs:
            start = _to_epoch(kwargs["logs_start_date"])
        else:
            hours = (
                int(window_hours)
                if window_hours is not None
                else (_DEFAULT_LOGS_WINDOW_HOURS)
            )
            start = end - hours * 3600

        kwargs["logs_start_date"] = start
        kwargs["logs_end_date"] = end
        return start, end

    def _post(self, method: str, data: dict[str, Any]) -> dict[str, Any]:
        body = {"api_key": self._config["token"], "format": "json", **data}
        response = self._session.post(f"{_BASE_URL}/{method}", data=body, timeout=30)
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitedSignal(
                retry_after=float(retry_after) if retry_after else None
            )
        response.raise_for_status()

        payload = response.json()
        if payload.get("stat") == "fail":
            error = payload.get("error") or {}
            message = str(error.get("message", "")).lower()
            if error.get("parameter_name") == "api_key":
                raise UnauthorizedSignal()
            if "too many requests" in message or "rate" in message:
                raise RateLimitedSignal()
            raise RuntimeError(
                f"UptimeRobot {method} failed: "
                f"{error.get('message') or error.get('type') or 'unknown error'}"
            )
        return payload
