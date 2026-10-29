"""Qualys TotalAppSec (Web Application Scanning) collector.

Raw ``requests`` against the WAS v3 search API (``/qps/rest/3.0/search/was/...``)
on the subscription's Qualys API server, no vendor SDK. Deliberately separate
from ``qualys.py``: VMDR's v2 API is XML over GET with a follow-up-URL cursor,
whereas WAS search is JSON over POST with a ``ServiceRequest`` body of
preferences and criteria filters — two different API families that share
nothing but a host and Basic auth.

The newer WAS v4 API (``/qps/rest/webapp/4.0``, July 2026) is not used: its
public reference was too thin at write time to build against with confidence,
and v3 remains supported under Basic auth. Subscription-level OAuth
(``/auth/oauth``) is not accepted by any WAS endpoint, so Basic auth as a
Qualys user it is; that user's scope bounds which web apps and findings are
visible.

Pagination: each search returns ``hasMoreRecords`` and ``lastId``. The cursor is
``lastId``; the next page re-sends the same criteria plus ``id GREATER lastId``
(strictly greater, per Qualys).

kwargs: ``filters`` — a list of Qualys search criteria dicts
(``{"field": ..., "operator": ..., "value": ...}``), ANDed together, passed
through verbatim. This is Qualys's own filter dialect; see the WAS API
reference for each resource's searchable fields.

Errors: QPS reports some failures as HTTP 200 with a non-``SUCCESS``
``responseCode`` (and ``responseErrorDetails``) rather than an HTTP status,
so the body is checked on every response. A 409 is Qualys's concurrency
limit, retried via ``RateLimitedSignal`` honouring ``X-RateLimit-ToWait-Sec``.
A 401, or an ``INVALID_CREDENTIALS`` responseCode (the check Qualys's own WAS
Burp extension makes), raises ``AuthenticationError`` straight away rather
than retrying: Basic auth has no token to refresh, so re-sending the same
credentials cannot succeed and each attempt counts towards Qualys's
failed-login lockout.

Resources: ``webapps``, ``findings``.

**Caveat:** built from Qualys's public WAS API documentation, whose search
samples are XML; the JSON envelope (``ServiceResponse.data[].<Entity>``) comes
from the separate JSON-support page. No live subscription was available to
verify this collector. Verify field names/nesting (notably the ``list``
wrappers on ``tags``/``cwe``/``owasp``/``wasc``) against a real response
before relying on it.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

import requests

from posture.base import Collector, PermissionDeniedSignal, RateLimitedSignal
from posture.exceptions import AuthenticationError

logger = logging.getLogger("posture.collectors.qualys_tas")

_WEBAPP_SEARCH_PATH = "/qps/rest/3.0/search/was/webapp"
_FINDING_SEARCH_PATH = "/qps/rest/3.0/search/was/finding"

_AUTH_HINT = (
    "check QUALYS_TAS_USERNAME (the login Qualys generated, not the display "
    "name) and QUALYS_TAS_PASSWORD, that API access is allowed for the user, "
    "and that the subscription includes the API (Qualys Community Edition "
    "does not)"
)

# Qualys QPS caps limitResults at 1000 per request.
_PAGE_SIZE = 1000
_REQUEST_TIMEOUT_SECONDS = 300

# resource -> (endpoint, entity key wrapping each record in `data`, verbose).
# Webapp search without verbose returns only a handful of fields (no tags,
# no OS); finding search's default response already carries every field the
# manifest reads, and verbose would add bulky request/response evidence.
_SEARCHES: dict[str, tuple[str, str, bool]] = {
    "webapps": (_WEBAPP_SEARCH_PATH, "WebApp", True),
    "findings": (_FINDING_SEARCH_PATH, "Finding", False),
}

MANIFEST: dict[str, dict[str, Any]] = {
    "webapps": {
        "endpoint": _WEBAPP_SEARCH_PATH,
        "columns": {
            "id": ("id", "int"),
            "name": ("name", "str"),
            "url": ("url", "str"),
            "os": ("os", "str"),
            "owner_username": ("owner.username", "str"),
            "scope": ("scope", "str"),
            "tags": ("tags.list", "json"),
            "is_scheduled": ("isScheduled", "bool"),
            "is_scanned": ("isScanned", "bool"),
            "last_scan_id": ("lastScan.id", "int"),
            "created_date": ("createdDate", "datetime"),
            "updated_date": ("updatedDate", "datetime"),
        },
    },
    "findings": {
        "endpoint": _FINDING_SEARCH_PATH,
        "columns": {
            "id": ("id", "int"),
            "unique_id": ("uniqueId", "str"),
            "qid": ("qid", "int"),
            "name": ("name", "str"),
            "type": ("type", "str"),
            "finding_type": ("findingType", "str"),
            "severity": ("severity", "int"),
            "status": ("status", "str"),
            "url": ("url", "str"),
            "potential": ("potential", "bool"),
            "detection_score": ("detectionScore", "int"),
            "cvss_v3_base": ("cvssV3.base", "float"),
            "cvss_v3_attack_vector": ("cvssV3.attackVector", "str"),
            "cwe": ("cwe.list", "json"),
            "owasp": ("owasp.list", "json"),
            "wasc": ("wasc.list", "json"),
            "webapp_id": ("webApp.id", "int"),
            "webapp_name": ("webApp.name", "str"),
            "webapp_url": ("webApp.url", "str"),
            "first_detected_date": ("firstDetectedDate", "datetime"),
            "last_detected_date": ("lastDetectedDate", "datetime"),
            "last_tested_date": ("lastTestedDate", "datetime"),
            "times_detected": ("timesDetected", "int"),
            "updated_date": ("updatedDate", "datetime"),
            "is_ignored": ("isIgnored", "bool"),
            "ignored_reason": ("ignoredReason", "str"),
            "ignored_date": ("ignoredDate", "datetime"),
        },
    },
}


class QualysTasCollector(Collector):
    env_prefix = "QUALYS_TAS"
    display_name = "Qualys TotalAppSec"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {
        "username": True,
        "password": True,
        "base_url": True,
    }
    url_config_keys: tuple[str, ...] = ("base_url",)

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        self._base_url = self._config["base_url"]

    def _authenticate(self) -> None:
        self._session.auth = (self._config["username"], self._config["password"])
        # Required by Qualys's VM/PC API for Basic auth; the WAS docs don't
        # list it, but it is harmless there and qualysapi sends it on WAS too.
        self._session.headers["X-Requested-With"] = "posture"
        self._session.headers["Accept"] = "application/json"
        self._session.headers["Content-Type"] = "application/json"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        search = _SEARCHES.get(resource)
        if search is None:
            raise ValueError(f"Unsupported resource '{resource}'")
        unknown = set(kwargs) - {"filters"}
        if unknown:
            raise ValueError(f"Unsupported kwargs for '{resource}': {sorted(unknown)}")
        path, entity, verbose = search

        criteria = list(kwargs.get("filters", []))
        if cursor is not None:
            criteria.append({"field": "id", "operator": "GREATER", "value": cursor})
        request: dict[str, Any] = {
            "preferences": {"limitResults": _PAGE_SIZE, "verbose": verbose}
        }
        if criteria:
            request["filters"] = {"Criteria": criteria}

        body = self._post_search(path, request, resource)
        records = [item[entity] for item in body.get("data") or []]
        if str(body.get("hasMoreRecords", "false")).lower() != "true":
            return records, None
        last_id = body.get("lastId")
        if last_id is None:
            # Ending here would silently hand back a partial snapshot.
            raise ValueError(
                f"Qualys TotalAppSec reported more '{resource}' records but no lastId"
            )
        return records, last_id

    def _post_search(
        self, path: str, request: dict[str, Any], resource: str
    ) -> dict[str, Any]:
        """POST one search and return its ServiceResponse, raising for both
        HTTP-level failures and QPS's HTTP-200 non-SUCCESS responseCodes."""
        response = self._session.post(
            self._base_url + path,
            json={"ServiceRequest": request},
            timeout=_REQUEST_TIMEOUT_SECONDS,
        )
        if response.status_code in (409, 429):
            wait = response.headers.get(
                "X-RateLimit-ToWait-Sec"
            ) or response.headers.get("Retry-After")
            raise RateLimitedSignal(retry_after=float(wait) if wait else None)
        if response.status_code == 401:
            raise AuthenticationError(
                f"Qualys TotalAppSec rejected the credentials (HTTP 401) for "
                f"'{resource}': {response.text[:200]}",
                source="qualys_tas",
                hint=_AUTH_HINT,
            )
        response.raise_for_status()

        body = response.json()["ServiceResponse"]
        code = body.get("responseCode")
        if code != "SUCCESS":
            detail = (body.get("responseErrorDetails") or {}).get("errorMessage", "")
            message = f"Qualys TotalAppSec returned {code} for '{resource}': {detail}"
            if code == "INVALID_CREDENTIALS":
                raise AuthenticationError(message, source="qualys_tas", hint=_AUTH_HINT)
            if code in ("UNAUTHORIZED", "INSUFFICIENT_PRIVILEGES"):
                raise PermissionDeniedSignal(message)
            raise requests.HTTPError(message, response=response)
        return body
