"""HTTP response-header collector.

Raw ``requests`` against a caller-supplied list of hosts, no vendor SDK and
no credential of any kind. Two things make this collector unlike every other
one in the codebase, both deliberate design decisions (see the posture
Citadel room, entries 232/233/234):

* **The host list is the scope boundary.** Every other collector takes a
  credential and gets whatever the vendor's IAM entitles it to — the vendor
  enforces the boundary. There is no such gatekeeper here, so the
  ``hosts=[...]`` list itself stands in as the authorisation/scope mechanism.
  ``hosts`` (config key / ``HTTP_HOSTS``, comma-separated, or the ``hosts``
  kwarg, a comma-separated string or a list — kwarg wins per the locked
  kwargs-override rule) defaults to empty, and an empty resolved list
  short-circuits ``_fetch_page`` before any request is made, so a generic
  loop over every registered source's resources makes zero network calls
  against this source unless an operator has deliberately named hosts.

* **Per-host failure handling, not all-or-nothing.** There are N independent
  hosts in one call; one host timing out or refusing a connection must not
  discard the other N-1. A network failure against a single host is captured
  as a row with ``ok=False`` and an ``error`` message rather than being
  allowed to propagate as ``IncompleteCollection``. A malformed scope entry
  — a host with no ``http://`` / ``https://`` scheme — is captured the same
  way: a failure row, not a raised exception, so it doesn't discard the rest
  of the batch either.

Output shape is tidy/long: one row per ``(host, header_name, header_value)``,
a fixed column set. A wide format (one column per header) was rejected
because header sets vary per host, which would make the schema shift under
the manifest-driven parse step every other collector relies on. A host that
failed outright contributes a single row with null ``header_name`` /
``header_value`` and the failure in ``error``.

Scheme and port are part of the host's identity, taken exactly as supplied —
``https://host:8443`` and ``https://host`` are two distinct queries, no
normalisation, no defaulting. Redirects are **not** followed
(``allow_redirects=False``): the host the caller named is the asset being
queried, so the response is captured as-is, including a 3xx status and its
``Location`` header (which simply becomes another header row). A caller who
wants the redirect target's headers makes a separate explicit call for it.

TLS verification is two-pass for ``https://`` targets: the verified handshake
is tried first, and only on an ``SSLError`` does the collector fall back to
``verify=False`` so the headers are still captured — recording the
verification failure reason in ``tls_error`` before falling back. The
nullable ``secure`` column reflects the outcome: null for ``http://``, true
if the verified handshake succeeded, false if it fell back to insecure.
Certificate facts (subject, issuer, expiry, SANs) and cipher/protocol
strength are out of scope — ``requests`` does not expose the former, and the
latter is ``sslyze``/``testssl.sh`` territory.
"""

from __future__ import annotations

import logging
import time
import warnings
from typing import Any, ClassVar

import requests
from urllib3.exceptions import InsecureRequestWarning

from posture.base import Collector

logger = logging.getLogger("posture.collectors.http")

_REQUEST_TIMEOUT_SECONDS = 10.0

MANIFEST: dict[str, dict[str, Any]] = {
    "headers": {
        "columns": {
            "host": ("host", "str"),
            "ok": ("ok", "bool"),
            "status_code": ("status_code", "int"),
            "secure": ("secure", "bool"),
            "tls_error": ("tls_error", "str"),
            "error": ("error", "str"),
            "duration_ms": ("duration_ms", "int"),
            "header_name": ("header_name", "str"),
            "header_value": ("header_value", "str"),
        }
    }
}


class HttpCollector(Collector):
    env_prefix = "HTTP"
    display_name = "HTTP headers"
    manifest = MANIFEST
    # No credential exists to require — declared anyway (as not-required) so
    # catalog()/generated docs document the hosts default the same way every
    # other collector's optional config is documented.
    config_keys: ClassVar[dict[str, bool]] = {"hosts": False}

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        self._default_hosts = _split_hosts(self._config.get("hosts"))

    def _authenticate(self) -> None:
        # No credential — the host list is the scope boundary, not an identity.
        pass

    def _resolve_hosts(self, kwargs: dict[str, Any]) -> list[str]:
        hosts = kwargs.get("hosts")
        if hosts is None:
            return self._default_hosts
        if isinstance(hosts, str):
            return _split_hosts(hosts)
        return [str(host).strip() for host in hosts if str(host).strip()]

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource != "headers":
            raise ValueError(f"Unknown resource '{resource}'")

        hosts = self._resolve_hosts(kwargs)
        if not hosts:
            return [], None

        timeout = float(kwargs.get("timeout", _REQUEST_TIMEOUT_SECONDS))
        index = cursor or 0
        host = hosts[index]
        records = self._probe_host(host, timeout)
        next_cursor = index + 1 if index + 1 < len(hosts) else None
        return records, next_cursor

    def _probe_host(self, host: str, timeout: float) -> list[dict[str, Any]]:
        scheme = host.split("://", 1)[0].lower() if "://" in host else ""
        if scheme not in ("http", "https"):
            # A malformed scope entry is the caller's mistake, but per-host
            # tolerance still applies — one bad entry must not discard the
            # rest of the batch. Surface it as a failure row, same shape as a
            # network failure, rather than raising.
            return [
                _failure_row(
                    host,
                    "Host has no http:// or https:// scheme. The scheme is "
                    "mandatory and not defaulted — pass 'http://' or "
                    "'https://' explicitly (a host may be listed under both).",
                    duration_ms=0,
                )
            ]

        started = time.monotonic()
        try:
            response, secure, tls_error = self._get(host, scheme, timeout)
        except requests.exceptions.RequestException as exc:
            duration_ms = round((time.monotonic() - started) * 1000)
            logger.warning(
                "host request failed",
                extra={"source": "http", "host": host, "error": str(exc)},
            )
            return [_failure_row(host, str(exc), duration_ms=duration_ms)]

        duration_ms = round((time.monotonic() - started) * 1000)
        base = {
            "host": host,
            "ok": True,
            "status_code": response.status_code,
            "secure": secure,
            "tls_error": tls_error,
            "error": None,
            "duration_ms": duration_ms,
        }
        return [
            {**base, "header_name": name, "header_value": value}
            for name, value in response.headers.items()
        ]

    def _get(
        self, host: str, scheme: str, timeout: float
    ) -> tuple[requests.Response, bool | None, str | None]:
        """Fetch ``host`` without following redirects.

        Returns ``(response, secure, tls_error)``. ``secure`` is ``None`` for
        http, ``True`` if the verified TLS handshake succeeded, ``False`` if
        verification failed and the request fell back to ``verify=False``;
        ``tls_error`` carries the verification failure reason in that last case.
        """
        if scheme == "http":
            return (
                self._session.get(host, allow_redirects=False, timeout=timeout),
                None,
                None,
            )

        try:
            response = self._session.get(
                host, allow_redirects=False, timeout=timeout, verify=True
            )
            return response, True, None
        except requests.exceptions.SSLError as exc:
            tls_error = str(exc)
            logger.warning(
                "TLS verification failed, retrying without verification",
                extra={"source": "http", "host": host, "error": tls_error},
            )
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", InsecureRequestWarning)
                response = self._session.get(
                    host, allow_redirects=False, timeout=timeout, verify=False
                )
            return response, False, tls_error


def _failure_row(host: str, error: str, *, duration_ms: int) -> dict[str, Any]:
    return {
        "host": host,
        "ok": False,
        "status_code": None,
        "secure": None,
        "tls_error": None,
        "error": error,
        "duration_ms": duration_ms,
        "header_name": None,
        "header_value": None,
    }


def _split_hosts(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return [str(item).strip() for item in value if str(item).strip()]
