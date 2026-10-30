"""Qualys TotalAppSec (Web Application Scanning) tables.

Raw ``requests`` against the WAS v3 search API (``/qps/rest/3.0/search/was/...``)
on the subscription's API server (``base_url``). A different API family from
``fo_api.py``: WAS search is JSON over POST with a ``ServiceRequest`` body of
preferences and criteria filters, sharing only the host and Basic auth.

The newer WAS v4 API (``/qps/rest/webapp/4.0``, July 2026) is not used: its
public reference was too thin at write time to build against with confidence,
and v3 remains supported under Basic auth. Subscription-level OAuth
(``/auth/oauth``) is not accepted by any WAS endpoint, so Basic auth as a
Qualys user it is; that user's scope bounds which web apps and findings are
visible.

Pagination: each search returns ``hasMoreRecords`` and ``lastId``. The cursor is
``lastId``; the next page re-sends the same criteria plus ``id GREATER lastId``
(strictly greater, per Qualys).

kwargs: ``filters``, a list of Qualys search criteria dicts
(``{"field": ..., "operator": ..., "value": ...}``), ANDed together, passed
through verbatim. This is Qualys's own filter dialect; see the WAS API
reference for each table's searchable fields.

Errors: QPS reports some failures as HTTP 200 with a non-``SUCCESS``
``responseCode`` (and ``responseErrorDetails``) rather than an HTTP status,
so the body is checked on every response. A 409 is Qualys's concurrency
limit, retried via ``RateLimitedSignal`` honouring ``X-RateLimit-ToWait-Sec``.
A 401, or an ``INVALID_CREDENTIALS`` responseCode (the check Qualys's own WAS
Burp extension makes), raises ``CredentialsRejected`` straight away rather
than retrying: Basic auth has no token to refresh, so re-sending the same
credentials cannot succeed and each attempt counts towards Qualys's
failed-login lockout.
"""

from __future__ import annotations

from typing import Any

import requests

from posture.base import PermissionDeniedSignal, RateLimitedSignal
from posture.collectors.qualys.errors import CredentialsRejected

_WEBAPP_SEARCH_PATH = "/qps/rest/3.0/search/was/webapp"
_FINDING_SEARCH_PATH = "/qps/rest/3.0/search/was/finding"

_AUTH_HINT = (
    "check QUALYS_USERNAME (the login Qualys generated, not the display name) "
    "and QUALYS_PASSWORD, that API access is allowed for the user, and that "
    "the subscription includes the API (Qualys Community Edition does not)"
)

# Qualys QPS caps limitResults at 1000 per request.
_PAGE_SIZE = 1000
_REQUEST_TIMEOUT_SECONDS = 300

# table -> (endpoint, entity key wrapping each record in `data`, verbose).
# Webapp search without verbose returns only a handful of fields (no tags,
# no OS); finding search's default response already carries every field the
# manifest reads, and verbose would add bulky request/response evidence.
_SEARCHES: dict[str, tuple[str, str, bool]] = {
    "webapps": (_WEBAPP_SEARCH_PATH, "WebApp", True),
    "webapps_findings": (_FINDING_SEARCH_PATH, "Finding", False),
}

MANIFEST: dict[str, dict[str, Any]] = {
    "webapps": {
        "endpoint": _WEBAPP_SEARCH_PATH,
        "columns": {
            "webapp_id": ("id", "str"),
            "name": ("name", "str"),
            "url": ("url", "str"),
            "os": ("os", "str"),
            "owner_username": ("owner.username", "str"),
            "scope": ("scope", "str"),
            "tags": ("tags.list", "json"),
            "is_scheduled": ("isScheduled", "bool"),
            "is_scanned": ("isScanned", "bool"),
            "last_scan_id": ("lastScan.id", "str"),
            "created": ("createdDate", "datetime"),
            "last_updated": ("updatedDate", "datetime"),
        },
    },
    "webapps_findings": {
        "endpoint": _FINDING_SEARCH_PATH,
        "columns": {
            "finding_id": ("id", "str"),
            "unique_id": ("uniqueId", "str"),
            "qid": ("qid", "str"),
            "title": ("name", "str"),
            "type": ("type", "str"),
            "finding_type": ("findingType", "str"),
            "severity": ("severity", "int"),
            "status": ("status", "str"),
            "url": ("url", "str"),
            "potential": ("potential", "bool"),
            "detection_score": ("detectionScore", "int"),
            "cvss3_base": ("cvssV3.base", "float"),
            "cvss3_attack_vector": ("cvssV3.attackVector", "str"),
            "cwe": ("cwe.list", "json"),
            "owasp": ("owasp.list", "json"),
            "wasc": ("wasc.list", "json"),
            "webapp_id": ("webApp.id", "str"),
            "webapp_name": ("webApp.name", "str"),
            "webapp_url": ("webApp.url", "str"),
            "first_found": ("firstDetectedDate", "datetime"),
            "last_found": ("lastDetectedDate", "datetime"),
            "last_tested": ("lastTestedDate", "datetime"),
            "times_detected": ("timesDetected", "int"),
            "last_updated": ("updatedDate", "datetime"),
            "is_ignored": ("isIgnored", "bool"),
            "ignored_reason": ("ignoredReason", "str"),
            "ignored_date": ("ignoredDate", "datetime"),
        },
    },
}


class WebappsApi:
    resources = tuple(_SEARCHES)

    def __init__(
        self, session: requests.Session, base_url: str, auth: tuple[str, str]
    ) -> None:
        self._session = session
        self._base_url = base_url
        self._auth = auth

    def fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        unknown = set(kwargs) - {"filters"}
        if unknown:
            raise ValueError(f"Unsupported kwargs for '{resource}': {sorted(unknown)}")
        path, entity, verbose = _SEARCHES[resource]

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
            auth=self._auth,
            headers={"Accept": "application/json"},
            timeout=_REQUEST_TIMEOUT_SECONDS,
        )
        if response.status_code in (409, 429):
            wait = response.headers.get(
                "X-RateLimit-ToWait-Sec"
            ) or response.headers.get("Retry-After")
            raise RateLimitedSignal(retry_after=float(wait) if wait else None)
        if response.status_code == 401:
            raise CredentialsRejected(
                f"Qualys TotalAppSec rejected the credentials (HTTP 401) for "
                f"'{resource}': {response.text[:200]}",
                source="qualys",
                hint=_AUTH_HINT,
            )
        response.raise_for_status()

        body = response.json()["ServiceResponse"]
        code = body.get("responseCode")
        if code != "SUCCESS":
            detail = (body.get("responseErrorDetails") or {}).get("errorMessage", "")
            message = f"Qualys TotalAppSec returned {code} for '{resource}': {detail}"
            if code == "INVALID_CREDENTIALS":
                raise CredentialsRejected(message, source="qualys", hint=_AUTH_HINT)
            if code in ("UNAUTHORIZED", "INSUFFICIENT_PRIVILEGES"):
                raise PermissionDeniedSignal(message)
            raise requests.HTTPError(message, response=response)
        return body
