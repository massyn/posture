"""Qualys VMDR collector.

Raw ``requests`` against the Qualys API v2 (``/api/2.0/fo/...``) — no vendor
SDK; it is generic REST once its two quirks are handled locally:

1. **XML, not JSON.** Every v2 endpoint returns XML. ``_xml_to_dict``
   converts each ``<HOST>``/``<VULN>``/``<DETECTION>`` element into a plain
   dict at fetch time (still the network phase, per CLAUDE.md's collect/parse
   split — this is response *shaping*, not business logic) so ``parse.py``
   never has to know XML exists. Only elements this collector actually reads
   are handled; Qualys's list-wrapper tags (``HOST``, ``VULN``, ``DETECTION``,
   ``CVE``, ``TAG``) are always coerced to a list even when a single child is
   present, since Qualys collapses a wrapper with exactly one child to a bare
   element and parse.py's derived-resource explosion requires a list.
2. **Pagination is a full follow-up URL, not a token.** A truncated response
   carries the complete next-page URL in ``RESPONSE/WARNING/URL`` — already
   including every original query param — so the cursor here is that URL
   itself, fetched with no additional params.

Auth is HTTP Basic (session-lifetime, no token to refresh) plus the
mandatory ``X-Requested-With`` header Qualys' v2 API rejects requests
without. A 409 usually signals Qualys' concurrency limit, mapped to the same
``RateLimitedSignal`` the base class already retries on (reactive handling)
— but Qualys also reuses HTTP 409 for permanent, non-throttling account
errors (e.g. CODE 2003, "registration must be completed before API requests
will be served"), carried in a ``<SIMPLE_RETURN><RESPONSE><CODE>``/``<TEXT>``
body rather than an ``X-RateLimit-ToWait-Sec`` header. Retrying those as if
they were a concurrency limit just burns the entire rate-limit retry budget
(up to 100 attempts) before failing with a misleading "rate limit exhausted"
error, so ``_FATAL_409_CODES`` are parsed out of the body and raised
immediately as ``AuthenticationError`` instead of ``RateLimitedSignal`` —
no retry, collection fails fast with the real reason.

Every response also carries ``X-RateLimit-Remaining``/``X-RateLimit-Limit``/
``X-RateLimit-ToWait-Sec`` even on a 200 — Qualys subscriptions cap total
calls per rolling window, separately from the concurrency limit. Those are
read after each request and, once ``Remaining`` hits 0, the next request
proactively sleeps for ``ToWait-Sec`` before firing rather than waiting to
be rejected with a 409 first (proactive pacing — see CLAUDE.md's "Rate
limiting" observability section for the reactive+proactive split this
mirrors). Both header sets are logged at DEBUG on every call.

Resources: ``hosts``, ``vulnerabilities`` (KnowledgeBase), and
``vulnerability_detections`` (derived from the per-host detection list —
fetched as ``host_detections`` internally, matching the
vulnerabilities/vulnerability_remediations shape in ``crowdstrike.py``).
"""

from __future__ import annotations

import logging
import time
from typing import Any
from xml.etree import ElementTree

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal
from posture.exceptions import AuthenticationError

logger = logging.getLogger("posture.collectors.qualys")

# /api/2.0/fo/asset/host/ is Qualys-deprecated (End-of-Service warning
# observed on responses, EOL notice included) in favour of /api/5.0 — same
# request params and XML response shape, only the path version changed.
_HOST_LIST_ENDPOINT = "/api/5.0/fo/asset/host/"
# /api/2.0/fo/knowledge_base/vuln/ carries the same EOS warning in favour of
# /api/4.0 — same request params and XML response shape, only the path
# version changed.
_KB_ENDPOINT = "/api/4.0/fo/knowledge_base/vuln/"
_HOST_DETECTION_ENDPOINT = "/api/2.0/fo/asset/host/vm/detection/"

_PAGE_SIZE = 1000

# KnowledgeBase pulls are a single unpaginated request (see `paginated=False`
# below) — for an operator running against the full/broad KB, the response
# body can legitimately take longer than a typical page fetch to arrive.
# 120s was tight enough to trip on that, well within the 2 transient-error
# retries CLAUDE.md's base-class contract already grants, so retrying didn't
# help. Widened per-request read timeout rather than the retry budget, since
# the problem is response size/latency, not flakiness.
_REQUEST_TIMEOUT_SECONDS = 600

# Qualys reuses HTTP 409 for permanent account errors, not just its
# concurrency limit. CODE 2003 = "Registration must be completed before API
# requests will be served for this account" — a setup problem the retry
# budget cannot resolve, so it's treated as fatal rather than throttling.
# CODE 1960 = "This API cannot be run again until N currently running
# instance(s) have finished" — a per-API single-concurrent-run limit (not
# the general concurrency limit the 409 retry path already handles), raised
# by another instance of the same API already in flight (e.g. triggered
# outside this collector, or a prior run that never terminated). Retrying
# just burns the rate-limit budget waiting on a run this process doesn't
# control and has no way to wait for, so it's treated as fatal too.
_FATAL_409_CODES = {"2003", "1960"}

# Qualys XML wraps repeated children in a "_LIST" element (HOST_LIST/HOST,
# VULN_LIST/VULN, DETECTION_LIST/DETECTION, CVE_LIST/CVE, TAGS/TAG) but
# collapses that wrapper to a single bare child element when only one is
# present. These tags are always coerced to a list so parse.py's
# record_path traversal doesn't have to special-case cardinality.
_ALWAYS_LIST_TAGS = {"HOST", "VULN", "DETECTION", "CVE", "TAG"}

MANIFEST: dict[str, dict[str, Any]] = {
    "hosts": {
        "columns": {
            "host_id": ("ID", "str"),
            "ip": ("IP", "str"),
            "ipv6": ("IPV6", "str"),
            "tracking_method": ("TRACKING_METHOD", "str"),
            "dns": ("DNS", "str"),
            "netbios": ("NETBIOS", "str"),
            "operating_system": ("OS", "str"),
            "qg_host_id": ("QG_HOSTID", "str"),
            "cloud_provider": ("CLOUD_PROVIDER", "str"),
            "last_boot": ("LAST_BOOT", "datetime"),
            "last_vuln_scan_datetime": ("LAST_VULN_SCAN_DATETIME", "datetime"),
            "last_vm_scanned_date": ("LAST_VM_SCANNED_DATE", "datetime"),
            "last_pc_scanned_date": ("LAST_PC_SCANNED_DATE", "datetime"),
            "agent_version": ("AGENT_INFO.AGENT_VERSION", "str"),
            "agent_status": ("AGENT_INFO.AGENT_STATUS", "str"),
            "agent_last_checked_in": ("AGENT_INFO.LAST_CHECKED_IN_DATE", "datetime"),
            "tags": ("TAGS.TAG", "json"),
        },
    },
    "vulnerabilities": {
        "columns": {
            "qid": ("QID", "str"),
            "vuln_type": ("VULN_TYPE", "str"),
            "severity_level": ("SEVERITY_LEVEL", "int"),
            "title": ("TITLE", "str"),
            "category": ("CATEGORY", "str"),
            "patchable": ("PATCHABLE", "bool"),
            "pci_flag": ("PCI_FLAG", "bool"),
            "published_datetime": ("PUBLISHED_DATETIME", "datetime"),
            "last_modified_datetime": (
                "LAST_SERVICE_MODIFICATION_DATETIME",
                "datetime",
            ),
            "cvss_base": ("CVSS.BASE", "float"),
            "cvss3_base": ("CVSS_V3.BASE", "float"),
            "cve_list": ("CVE_LIST.CVE", "json"),
        },
    },
    "vulnerability_detections": {
        "derived_from": "host_detections",
        "record_path": "DETECTION_LIST.DETECTION",
        "columns": {
            "host_id": ("$parent.ID", "str"),
            "host_ip": ("$parent.IP", "str"),
            "host_dns": ("$parent.DNS", "str"),
            "host_os": ("$parent.OS", "str"),
            "qid": ("QID", "str"),
            "detection_type": ("TYPE", "str"),
            "severity": ("SEVERITY", "int"),
            "port": ("PORT", "int"),
            "protocol": ("PROTOCOL", "str"),
            "results": ("RESULTS", "str"),
            "status": ("STATUS", "str"),
            "first_found": ("FIRST_FOUND_DATETIME", "datetime"),
            "last_found": ("LAST_FOUND_DATETIME", "datetime"),
            "last_tested": ("LAST_TEST_DATETIME", "datetime"),
            "last_updated": ("LAST_UPDATE_DATETIME", "datetime"),
            "is_ignored": ("IS_IGNORED", "bool"),
            "is_disabled": ("IS_DISABLED", "bool"),
        },
    },
}


class QualysCollector(Collector):
    env_prefix = "QUALYS"
    manifest = MANIFEST
    required_config_keys = ("username", "password", "base_url")

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._base_url = self._config["base_url"].rstrip("/")
        # Proactive pacing state, set from the previous response's
        # X-RateLimit-* headers (see _request_xml). None until a request has
        # been made; a request is never delayed before we've actually seen a
        # window count.
        self._rate_limit_remaining: int | None = None
        self._rate_limit_wait_seconds: float | None = None

    def _authenticate(self) -> None:
        # Basic auth is stateless — no token to fetch, so nothing to validate
        # eagerly here. A live check would have to run outside
        # _request_with_retry (auth happens before pagination starts), which
        # would bypass its 409/401 handling entirely; instead credentials are
        # validated by the first real request, which does go through it.
        self._session.auth = (self._config["username"], self._config["password"])
        # Mandatory on every Qualys v2 call — omitting it is rejected outright.
        self._session.headers["X-Requested-With"] = "posture"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "hosts":
            return self._fetch_list_page(
                cursor,
                url=self._base_url + _HOST_LIST_ENDPOINT,
                params={
                    "action": "list",
                    "details": "All/AGs",
                    "show_tags": 1,
                    **kwargs,
                },
                list_path=("RESPONSE", "HOST_LIST", "HOST"),
            )
        if resource == "vulnerabilities":
            return self._fetch_list_page(
                cursor,
                url=self._base_url + _KB_ENDPOINT,
                params={"action": "list", "details": "All", **kwargs},
                list_path=("RESPONSE", "VULN_LIST", "VULN"),
                # KnowledgeBase rejects `truncation_limit` outright (400) —
                # unlike the asset/host/* endpoints, it isn't a paginated
                # list API and doesn't accept the param at all.
                paginated=False,
            )
        if resource == "host_detections":
            return self._fetch_list_page(
                cursor,
                url=self._base_url + _HOST_DETECTION_ENDPOINT,
                params={"action": "list", **kwargs},
                list_path=("RESPONSE", "HOST_LIST", "HOST"),
            )
        raise ValueError(f"Unsupported resource '{resource}'")

    def _fetch_list_page(
        self,
        cursor: Any,
        *,
        url: str,
        params: dict[str, Any],
        list_path: tuple[str, ...],
        paginated: bool = True,
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            root = self._request_xml(cursor, params=None)
        elif paginated:
            root = self._request_xml(
                url, params={"truncation_limit": _PAGE_SIZE, **params}
            )
        else:
            root = self._request_xml(url, params=params)

        records = [
            _xml_to_dict(elem) for elem in root.findall("./" + "/".join(list_path))
        ]
        url_elem = root.find("./RESPONSE/WARNING/URL")
        next_cursor = (
            url_elem.text.strip() if url_elem is not None and url_elem.text else None
        )
        return records, next_cursor

    def _request_xml(
        self, url: str, *, params: dict[str, Any] | None
    ) -> ElementTree.Element:
        self._pace_request()
        response = self._session.get(
            url, params=params, timeout=_REQUEST_TIMEOUT_SECONDS
        )
        self._record_rate_limit_headers(response.headers)

        if response.status_code == 401:
            raise UnauthorizedSignal()
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
                hint = (
                    "another instance of this API is already running on "
                    "this Qualys account and must finish before this one "
                    "can — this is not a rate limit and will not resolve "
                    "by retrying"
                    if error_code == "1960"
                    else "check the account's registration/activation status "
                    "in the Qualys portal — this is not a rate limit and "
                    "will not resolve by retrying"
                )
                raise AuthenticationError(
                    f"Qualys rejected the request (CODE {error_code}): "
                    f"{error_text or 'no message'}",
                    source="qualys",
                    hint=hint,
                )
            wait = response.headers.get("X-RateLimit-ToWait-Sec")
            raise RateLimitedSignal(retry_after=float(wait) if wait else None)
        response.raise_for_status()
        return ElementTree.fromstring(response.content)

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


def _parse_simple_return_error(content: bytes) -> tuple[str | None, str | None]:
    """Pull CODE/TEXT out of a Qualys <SIMPLE_RETURN> error body.

    Used only to classify a 409 as fatal vs. throttling — a body that isn't
    a SIMPLE_RETURN (or is empty, as a genuine concurrency-limit 409 usually
    is) yields (None, None), which is never in _FATAL_409_CODES, so it falls
    through to the existing rate-limit retry path unchanged.
    """
    try:
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
