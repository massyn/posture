"""Recorded Future collector.

Raw ``requests`` against the standard Recorded Future REST API — generic
REST with a single ``X-RFToken`` header; nothing here needs vendor machinery
the base class can't already generalise.

Resources:

- ``alerts`` / ``alert_hits`` — ``GET /alert/v3``, offset pagination via
  ``limit``/``from``. The vendor caps ``limit + from`` at 1000 — pagination
  stops there even if more alerts exist server-side; this is a documented
  API ceiling, not a bug in this collector. ``alert_hits`` is a derived
  resource exploding each alert's nested ``hits`` list, joined back to
  ``alerts`` via ``alert_id``.
- ``vulnerability_risklist`` — ``GET /vulnerability/risklist``. Unlike every
  other resource in this codebase, this endpoint returns a bulk CSV file
  (no JSON envelope, no pagination) rather than a paginated JSON list — the
  vendor designed it as a watchlist export, not a listing API. ``_fetch_page``
  parses the CSV into records itself before handing off to ``parse()``, and
  ``EvidenceDetails`` (a JSON-encoded array embedded in one CSV cell) is
  decoded to a real list first so it round-trips through the ``json`` column
  type the same way any other collector's nested list would.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from typing import Any, ClassVar

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger = logging.getLogger("posture.collectors.recorded_future")

_BASE_URL = "https://api.recordedfuture.com"
_ALERTS_PATH = "/alert/v3"
_RISKLIST_PATH = "/vulnerability/risklist"

_ALERTS_PAGE_LIMIT = 200
# Vendor-documented ceiling: limit + from must not exceed 1000.
_ALERTS_MAX_TOTAL = 1000
# Explicitly requested so `hits` (needed for the alert_hits derived
# resource) is always present — the vendor's own default field set omits it.
_ALERTS_DEFAULT_FIELDS = "id,title,type,rule,review,url,hits"

_ALERT_KWARGS = frozenset(
    {
        "triggered",
        "assignee",
        "statusInPortal",
        "alertRule",
        "freetext",
        "orderby",
        "direction",
        "fields",
        "taggedText",
    }
)
_RISKLIST_KWARGS = frozenset({"list"})

MANIFEST: dict[str, dict[str, Any]] = {
    "alerts": {
        "endpoint": _ALERTS_PATH,
        "columns": {
            "id": ("id", "str"),
            "title": ("title", "str"),
            "type": ("type", "str"),
            "rule_id": ("rule.id", "str"),
            "rule_name": ("rule.name", "str"),
            "rule_portal_url": ("rule.url.portal", "str"),
            "status": ("review.status", "str"),
            "status_in_portal": ("review.status_in_portal", "str"),
            "assignee": ("review.assignee", "str"),
            "note": ("review.note", "str"),
            "url_api": ("url.api", "str"),
            "url_portal": ("url.portal", "str"),
        },
    },
    "alert_hits": {
        "derived_from": "alerts",
        "record_path": "hits",
        "columns": {
            "alert_id": ("$parent.id", "str"),
            "hit_id": ("id", "str"),
            "entities": ("entities", "json"),
            "document_title": ("document.title", "str"),
            "document_url": ("document.url", "str"),
            "document_source_id": ("document.source.id", "str"),
            "document_source_name": ("document.source.name", "str"),
            "fragment": ("fragment", "str"),
        },
    },
    "vulnerability_risklist": {
        "endpoint": _RISKLIST_PATH,
        "columns": {
            "name": ("Name", "str"),
            "risk": ("Risk", "int"),
            "risk_string": ("RiskString", "str"),
            "evidence_details": ("EvidenceDetails", "json"),
        },
    },
}


class RecordedFutureCollector(Collector):
    env_prefix = "RECORDEDFUTURE"
    display_name = "Recorded Future"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {"token": True}

    def _authenticate(self) -> None:
        self._session.headers["X-RFToken"] = self._config["token"]

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "alerts":
            return self._fetch_alerts_page(kwargs, cursor)
        if resource == "vulnerability_risklist":
            if cursor is not None:
                return [], None
            return self._fetch_risklist_page(kwargs)
        raise ValueError(f"Unsupported resource '{resource}'")

    def _fetch_alerts_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        unknown = set(kwargs) - _ALERT_KWARGS
        if unknown:
            raise ValueError(f"Unsupported kwargs for 'alerts': {sorted(unknown)}")

        offset = cursor if cursor is not None else 0
        params: dict[str, Any] = {
            "limit": _ALERTS_PAGE_LIMIT,
            "from": offset,
            "fields": _ALERTS_DEFAULT_FIELDS,
        }
        params.update(kwargs)

        response = self._get(_BASE_URL + _ALERTS_PATH, params=params)
        payload = response.json()
        records = payload.get("data") or []
        counts = payload.get("counts") or {}
        total = int(counts.get("total", len(records)))
        next_offset = offset + len(records)

        if not records or next_offset >= total or next_offset >= _ALERTS_MAX_TOTAL:
            return records, None
        return records, next_offset

    def _fetch_risklist_page(
        self, kwargs: dict[str, Any]
    ) -> tuple[list[dict[str, Any]], Any]:
        unknown = set(kwargs) - _RISKLIST_KWARGS
        if unknown:
            raise ValueError(
                f"Unsupported kwargs for 'vulnerability_risklist': {sorted(unknown)}"
            )

        params: dict[str, Any] = {"format": "csv/splunk"}
        params.update(kwargs)
        response = self._get(_BASE_URL + _RISKLIST_PATH, params=params)

        records = []
        for row in csv.DictReader(io.StringIO(response.text)):
            evidence = row.get("EvidenceDetails")
            if evidence:
                try:
                    row["EvidenceDetails"] = json.loads(evidence)
                except json.JSONDecodeError:
                    logger.warning(
                        "Unparseable EvidenceDetails for vulnerability_risklist row",
                        extra={"source": "recorded_future", "sample": evidence[:200]},
                    )
                    row["EvidenceDetails"] = None
            records.append(row)
        return records, None

    def _get(self, url: str, params: dict[str, Any] | None = None) -> Any:
        response = self._session.get(url, params=params, timeout=30)
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitedSignal(
                retry_after=float(retry_after) if retry_after else None
            )
        if response.status_code == 401:
            raise UnauthorizedSignal()
        response.raise_for_status()
        return response
