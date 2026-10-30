"""Client for the Qualys ``/api/N.0/fo/...`` XML API family (VMDR and Policy
Compliance).

Raw ``requests``, no vendor SDK; it is generic REST once its two quirks are
handled locally:

1. **XML, not JSON.** Every ``/fo/`` endpoint returns XML. ``_xml_to_dict``
   converts each list element (``<HOST>``, ``<VULN>``, ``<POLICY>``, ...)
   into a plain dict at fetch time (still the network phase, per the
   collect/parse split — this is response *shaping*, not business logic) so
   ``parse.py`` never has to know XML exists. Qualys's list-wrapper tags
   (``_ALWAYS_LIST_TAGS``) are always coerced to a list even when a single
   child is present, since Qualys collapses a wrapper with exactly one child
   to a bare element and parse.py's derived-resource explosion requires a
   list.
2. **Pagination is a full follow-up URL, not a token.** A truncated response
   carries the complete next-page URL in ``RESPONSE/WARNING/URL`` — already
   including every original query param — so the cursor is that URL itself,
   fetched with no additional params.

Auth is HTTP Basic (no token to refresh) plus the mandatory
``X-Requested-With`` header, set session-wide by the collector. A 401 (CODE
2000) or account-level 403 (CODE 2002/2012) is raised straight away with
Qualys's CODE and TEXT, not retried: re-sending the same credentials cannot
succeed and each attempt counts towards Qualys's failed-login lockout. The
ones that reject the user rather than one API (``_ACCOUNT_REJECTED_CODES``)
are ``CredentialsRejected``, which stops the collector sending any further
request this run; 2012 (this API not licensed) is a plain
``AuthenticationError`` failing only its own table. Any other 403 is a
``PermissionDeniedSignal``, failing only the table that asked for it (a
module the subscription doesn't licence).

A 409 usually signals Qualys's concurrency limit, mapped to the
``RateLimitedSignal`` the base class retries on — but Qualys also reuses HTTP
409 for permanent account errors (e.g. CODE 2003, "registration must be
completed before API requests will be served"), carried in a
``<SIMPLE_RETURN><RESPONSE><CODE>``/``<TEXT>`` body rather than an
``X-RateLimit-ToWait-Sec`` header. Retrying those burns the whole rate-limit
retry budget (up to 100 attempts) before failing with a misleading "rate
limit exhausted" error, so ``_FATAL_409_CODES`` are raised immediately as
``AuthenticationError`` instead.

Every response also carries ``X-RateLimit-Remaining``/``X-RateLimit-Limit``/
``X-RateLimit-ToWait-Sec`` even on a 200 — Qualys subscriptions cap total
calls per rolling window, separately from the concurrency limit. Those are
read after each request and, once ``Remaining`` hits 0, the next request
proactively sleeps for ``ToWait-Sec`` before firing rather than waiting to be
rejected with a 409 first. Both header sets are logged at DEBUG on every call.
"""

from __future__ import annotations

import logging
import time
from typing import Any
from xml.etree import ElementTree

import requests

from posture.base import PermissionDeniedSignal, RateLimitedSignal
from posture.collectors.qualys.errors import CredentialsRejected
from posture.exceptions import AuthenticationError

logger = logging.getLogger("posture.collectors.qualys")

_PAGE_SIZE = 1000

# KnowledgeBase pulls are a single unpaginated request (see `paginated=False`
# in vm.py) — for an operator running against the full/broad KB, the response
# body can legitimately take longer than a typical page fetch to arrive.
# 120s was tight enough to trip on that, well within the 2 transient-error
# retries the base-class contract already grants, so retrying didn't help.
# Widened per-request read timeout rather than the retry budget, since the
# problem is response size/latency, not flakiness.
_REQUEST_TIMEOUT_SECONDS = 600

# Qualys reuses HTTP 409 for permanent account errors, not just its
# concurrency limit. CODE 2003 = "Registration must be completed before API
# requests will be served for this account" — a setup problem the retry
# budget cannot resolve, so it's treated as fatal rather than throttling.
# CODE 2011 = "SecureID authentication is required for this account, so API
# access is blocked" — likewise permanent.
# CODE 1960 = "This API cannot be run again until N currently running
# instance(s) have finished" — a per-API single-concurrent-run limit (not
# the general concurrency limit the 409 retry path already handles), raised
# by another instance of the same API already in flight (e.g. triggered
# outside this collector, or a prior run that never terminated). Retrying
# just burns the rate-limit budget waiting on a run this process doesn't
# control and has no way to wait for, so it's treated as fatal too.
_FATAL_409_CODES = {"2003", "2011", "1960"}

# Hints for the account-level CODEs in Qualys's API error table (appendix D):
# 2000 arrives as HTTP 401, 2002/2012 as 403, the rest as 409. None of them
# resolves by retrying.
_ACCOUNT_ERROR_HINTS = {
    "2000": "check the username (the login Qualys generated, not the display "
    "name) and password, that API access is ticked under the user's role, and "
    "that the subscription includes the API (Qualys Community Edition does "
    "not)",
    "2002": "the user account is inactive; reactivate it in the Qualys portal",
    "2003": "check the account's registration/activation status in the Qualys "
    "portal; this is not a rate limit and will not resolve by retrying",
    "2011": "SecureID is enabled for this account, which blocks API access; "
    "use an account without SecureID",
    "2012": "the subscription's licence does not include this API; ask Qualys "
    "support or your account manager to enable API access",
    "1960": "another instance of this API is already running on this Qualys "
    "account and must finish before this one can; this is not a rate limit "
    "and will not resolve by retrying",
}
_AUTH_403_CODES = {"2002", "2012"}
# The CODEs that reject the user or account rather than one API (2012 is
# one API not licensed, 1960 one API busy): no request as this user can
# succeed, so they raise CredentialsRejected. 2000 always arrives as a 401.
_ACCOUNT_REJECTED_CODES = {"2002", "2003", "2011"}

# Qualys XML wraps repeated children in a "_LIST" element (HOST_LIST/HOST,
# VULN_LIST/VULN, DETECTION_LIST/DETECTION, CVE_LIST/CVE, TAGS/TAG,
# CONTROL_LIST/CONTROL) but collapses that wrapper to a single bare child
# element when only one is present. These tags are always coerced to a list
# so parse.py's record_path traversal doesn't have to special-case
# cardinality.
_ALWAYS_LIST_TAGS = {"HOST", "VULN", "DETECTION", "CVE", "TAG", "CONTROL"}


class FoApi:
    """One subscription's ``/fo/`` API: Basic-auth XML GETs with pacing."""

    def __init__(
        self, session: requests.Session, base_url: str, auth: tuple[str, str]
    ) -> None:
        self._session = session
        self._base_url = base_url
        self._auth = auth
        # Proactive pacing state, set from the previous response's
        # X-RateLimit-* headers (see _request_xml). None until a request has
        # been made; a request is never delayed before we've actually seen a
        # window count.
        self._rate_limit_remaining: int | None = None
        self._rate_limit_wait_seconds: float | None = None

    def fetch_list_page(
        self,
        cursor: str | None,
        *,
        path: str,
        params: dict[str, Any],
        list_path: tuple[str, ...],
        paginated: bool = True,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Fetch one page of ``list_path`` records from ``path``, or the
        follow-up URL ``cursor`` when resuming. Returns (records, next URL)."""
        if cursor is not None:
            response = self._request_xml(cursor, params=None)
        elif paginated:
            response = self._request_xml(
                self._base_url + path,
                params={"truncation_limit": _PAGE_SIZE, **params},
            )
        else:
            response = self._request_xml(self._base_url + path, params=params)

        warning_url_path = ("RESPONSE", "WARNING", "URL")
        records: list[dict[str, Any]] = []
        next_cursor: str | None = None
        stack: list[str] = []
        try:
            # The KnowledgeBase resource has no server-side pagination
            # (`truncation_limit` is rejected outright) and a full-catalogue
            # pull comfortably exceeds 2 GiB of XML. `ElementTree.fromstring`
            # hands the whole body to expat in one call, whose length
            # argument is a C `int` — past ~2 GiB that overflows with
            # `OverflowError: size does not fit in an int`. Streaming with
            # `iterparse` over the raw socket and clearing each record element
            # once consumed keeps peak memory to "one record" instead of "the
            # whole tree" and never hands expat more than a bounded chunk at
            # a time.
            response.raw.decode_content = True
            # xml.etree is XXE/entity-bomb vulnerable on Python <=3.10, but
            # this parses an authenticated Qualys API response, not
            # attacker-controlled input — accepted risk, no defusedxml dep.
            for event, elem in ElementTree.iterparse(
                response.raw, events=("start", "end")
            ):
                if event == "start":
                    stack.append(elem.tag)
                    continue
                # `list_path`/`warning_url_path` are relative to the document
                # root, whose own tag varies by endpoint
                # (`KNOWLEDGE_BASE_VULN_LIST_OUTPUT` vs `SIMPLE_RETURN` etc.)
                # and isn't part of either path — drop it before comparing.
                current_path = tuple(stack[1:])
                stack.pop()
                if current_path == list_path:
                    records.append(_xml_to_dict(elem))
                    elem.clear()
                elif current_path == warning_url_path:
                    next_cursor = elem.text.strip() if elem.text else None
        finally:
            response.close()

        return records, next_cursor

    def _request_xml(self, url: str, *, params: dict[str, Any] | None) -> Any:
        self._pace_request()
        response = self._session.get(
            url,
            params=params,
            auth=self._auth,
            timeout=_REQUEST_TIMEOUT_SECONDS,
            stream=True,
        )
        self._record_rate_limit_headers(response.headers)

        if response.status_code in (401, 403):
            error_code, error_text = _parse_simple_return_error(response.content)
            response.close()
            message = (
                f"Qualys rejected the request (HTTP {response.status_code}, "
                f"CODE {error_code}): {error_text or 'no message'}"
            )
            # Basic auth has no session or token to refresh, so re-sending the
            # same credentials can never succeed, and every rejected attempt
            # counts towards Qualys's failed-login lockout. Fail on the first.
            if response.status_code == 401 or error_code in _AUTH_403_CODES:
                raise _account_error(response.status_code, error_code, message)
            raise PermissionDeniedSignal(message)
        if response.status_code == 409:
            error_code, error_text = _parse_simple_return_error(response.content)
            # Headers/body go into the message text itself, not `extra` —
            # a plain "%(message)s" formatter (e.g. logging.basicConfig's
            # default) silently drops `extra` fields, so a caller relying on
            # that formatter would never see them.
            logger.debug(
                "qualys 409: code=%s url=%s headers=%s body=%s",
                error_code,
                response.url,
                dict(response.headers),
                response.text,
                extra={"source": "qualys"},
            )
            if error_code in _FATAL_409_CODES:
                raise _account_error(
                    409,
                    error_code,
                    f"Qualys rejected the request (CODE {error_code}): "
                    f"{error_text or 'no message'}",
                )
            wait = response.headers.get("X-RateLimit-ToWait-Sec")
            raise RateLimitedSignal(retry_after=float(wait) if wait else None)
        response.raise_for_status()
        return response

    def _pace_request(self) -> None:
        # Proactive half of the rate-limit handling: once the previous
        # response reported its per-window call budget exhausted, wait the
        # window out here instead of firing anyway and taking a reactive 409.
        if self._rate_limit_remaining is not None and self._rate_limit_remaining <= 0:
            wait = self._rate_limit_wait_seconds or 1.0
            logger.info(
                "qualys rate-limit window exhausted, pacing next request",
                extra={"source": "qualys", "wait_seconds": wait},
            )
            time.sleep(wait)

    def _record_rate_limit_headers(self, headers: Any) -> None:
        limit = headers.get("X-RateLimit-Limit")
        remaining = headers.get("X-RateLimit-Remaining")
        to_wait = headers.get("X-RateLimit-ToWait-Sec")
        concurrency_limit = headers.get("Concurrency-Limit-Limit")
        concurrency_running = headers.get("Concurrency-Limit-Running")

        logger.debug(
            "qualys rate-limit headers",
            extra={
                "source": "qualys",
                "rate_limit": limit,
                "rate_limit_remaining": remaining,
                "rate_limit_to_wait_seconds": to_wait,
                "concurrency_limit": concurrency_limit,
                "concurrency_running": concurrency_running,
            },
        )

        self._rate_limit_remaining = int(remaining) if remaining is not None else None
        self._rate_limit_wait_seconds = float(to_wait) if to_wait is not None else None


def _account_error(status: int, code: str | None, message: str) -> AuthenticationError:
    """The error for an account-level refusal: ``CredentialsRejected`` when it
    refuses the user itself (any 401, or ``_ACCOUNT_REJECTED_CODES``), so the
    collector sends nothing more this run; otherwise a plain
    ``AuthenticationError`` that fails only the table that asked."""
    error = (
        CredentialsRejected
        if status == 401 or code in _ACCOUNT_REJECTED_CODES
        else AuthenticationError
    )
    hint = _ACCOUNT_ERROR_HINTS.get(code or "", _ACCOUNT_ERROR_HINTS["2000"])
    return error(message, source="qualys", hint=hint)


def _parse_simple_return_error(content: bytes) -> tuple[str | None, str | None]:
    """Pull CODE/TEXT out of a Qualys <SIMPLE_RETURN> error body.

    Used only to classify a 409 as fatal vs. throttling — a body that isn't
    a SIMPLE_RETURN (or is empty, as a genuine concurrency-limit 409 usually
    is) yields (None, None), which is never in _FATAL_409_CODES, so it falls
    through to the existing rate-limit retry path unchanged.
    """
    try:
        # xml.etree is XXE/entity-bomb vulnerable on Python <=3.10, but this
        # parses an authenticated Qualys API response, not attacker-
        # controlled input — accepted risk, no defusedxml dep.
        root = ElementTree.fromstring(content)
    except ElementTree.ParseError:
        return None, None
    code_elem = root.find("./RESPONSE/CODE")
    text_elem = root.find("./RESPONSE/TEXT")
    code = code_elem.text.strip() if code_elem is not None and code_elem.text else None
    text = text_elem.text.strip() if text_elem is not None and text_elem.text else None
    return code, text


def _xml_to_dict(elem: ElementTree.Element) -> dict[str, Any] | str | None:
    children = list(elem)
    if not children:
        text = (elem.text or "").strip()
        return text or None

    result: dict[str, Any] = {}
    for child in children:
        tag = child.tag
        value = _xml_to_dict(child)
        if tag in _ALWAYS_LIST_TAGS:
            result.setdefault(tag, [])
            result[tag].append(value)
        elif tag in result:
            existing = result[tag]
            if isinstance(existing, list):
                existing.append(value)
            else:
                result[tag] = [existing, value]
        else:
            result[tag] = value
    return result
