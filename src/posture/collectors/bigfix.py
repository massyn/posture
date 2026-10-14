"""HCL BigFix collector.

Raw ``requests`` against a BigFix root server's REST API, no vendor SDK.
BigFix is almost always self-hosted, so ``endpoint`` is required config — the
root server's base URL including its port (``https://bigfix.example.com:52311``),
same "operator-supplied, normalized host" shape as Tenable.sc's ``endpoint``.
Auth is HTTP Basic as a BigFix console operator (local or LDAP); the operator's
own visibility bounds what every query returns.

Every resource is one Session Relevance query POSTed to ``/api/query`` with
``output=json``, not a walk of the XML resource endpoints (``/api/computers``,
``/api/fixlets``) — one round trip per resource instead of a per-computer
fan-out. The server answers ``{"result": [[...], ...], "plural": ..., "type":
...}``: each row is a relevance tuple, i.e. a positional list. ``_fetch_page``
zips each tuple with its resource's field names into a dict before parse.py
ever sees it — the same "transform at fetch time" shape ``qualys.py`` uses for
XML. A resource's field names and relevance expressions are declared together
in ``_QUERIES`` so the two can't drift apart.

Every optional inspector is wrapped in ``if exists ... then ... else ""``: a
singular relevance expression that refers to a nonexistent object (a computer
that has never reported its OS, a Fixlet with no CVE list) fails the whole
query, not just that row.

kwargs: ``whose`` — a Session Relevance clause applied to each row's underlying
object (``bes computer`` for ``computers``, ``bes fixlet`` for ``fixlets``,
``bes fixlet result`` for ``fixlet_results``), ANDed onto the resource's
default filter. This is BigFix's own query dialect, passed through verbatim.

TLS: root servers commonly present a self-signed or internal-CA certificate on
port 52311. ``ca_bundle`` points certificate verification at a PEM CA bundle;
``insecure`` disables verification entirely. Both are applied to this
collector's own requests only — the shared base class is untouched.

Resources: ``computers``, ``fixlets``, ``fixlet_results``.

**Caveat:** built from HCL's public REST API and Session Relevance
documentation — no live root server was available to verify this collector.
The JSON shape of tuple results and the exact inspector names are the
lower-confidence parts. ``fixlet_results`` is a single unpaginated request
(``/api/query`` has no paging); on a large estate it may be slow, hence the
long request timeout. Verify against a real deployment before relying on it.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, ClassVar

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger = logging.getLogger("posture.collectors.bigfix")

_QUERY_PATH = "/api/query"

# A single relevance query is the whole resource — there is no paging to
# split a large result across requests, so the timeout has to cover the
# server evaluating and serialising everything in one go.
_QUERY_TIMEOUT_SECONDS = 600

# BigFix renders `time` as e.g. "Tue, 13 Oct 2026 10:00:00 +0000" and `date`
# as "Tue, 13 Oct 2026".
_TIME_FORMAT = {"format": "%a, %d %b %Y %H:%M:%S %z"}
_DATE_FORMAT = {"format": "%a, %d %b %Y"}

_TRUE_STRINGS = frozenset({"true", "1", "yes"})
_FALSE_STRINGS = frozenset({"false", "0", "no", ""})

# Fixlets (not Tasks/Analyses) currently relevant on at least one computer.
_RELEVANT_FIXLETS = "fixlet flag of it and applicable computer count of it > 0"


def _optional(expr: str) -> str:
    return f'(if exists ({expr}) then ({expr}) as string else "")'


# resource -> (ordered (field, relevance) pairs, set expression). The set
# expression's "{whose}" slot takes the operator's `whose` kwarg (default
# "true").
_QUERIES: dict[str, tuple[tuple[tuple[str, str], ...], str]] = {
    "computers": (
        (
            ("id", "id of it"),
            ("name", _optional("name of it")),
            ("operating_system", _optional("operating system of it")),
            ("cpu", _optional("cpu of it")),
            ("computer_type", _optional("computer type of it")),
            ("agent_type", _optional("agent type of it")),
            ("agent_version", _optional("agent version of it")),
            ("ip_addresses", 'concatenation ", " of (ip addresses of it as string)'),
            ("user_names", 'concatenation ", " of user names of it'),
            ("relay_server", _optional("relay server of it")),
            ("locked", "locked flag of it"),
            ("last_report_time", _optional("last report time of it")),
        ),
        "bes computers whose ({whose})",
    ),
    "fixlets": (
        (
            ("id", "id of it"),
            ("site_name", "name of site of it"),
            ("name", "name of it"),
            ("category", _optional("category of it")),
            ("source", _optional("source of it")),
            ("source_id", _optional("source id of it")),
            ("source_severity", _optional("source severity of it")),
            ("source_release_date", _optional("source release date of it")),
            ("cve_ids", _optional("cve id list of it")),
            ("applicable_computer_count", "applicable computer count of it"),
        ),
        f"bes fixlets whose ({_RELEVANT_FIXLETS} and ({{whose}}))",
    ),
    "fixlet_results": (
        (
            ("computer_id", "id of computer of it"),
            ("computer_name", _optional("name of computer of it")),
            ("fixlet_id", "id of fixlet of it"),
            ("fixlet_site_name", "name of site of fixlet of it"),
            ("fixlet_name", "name of fixlet of it"),
            ("source_severity", _optional("source severity of fixlet of it")),
            ("first_became_relevant", _optional("first became relevant of it")),
            ("last_became_relevant", _optional("last became relevant of it")),
        ),
        (
            "results whose (relevant flag of it and ({whose})) of bes fixlets "
            f"whose ({_RELEVANT_FIXLETS})"
        ),
    ),
}

MANIFEST: dict[str, dict[str, Any]] = {
    "computers": {
        "endpoint": _QUERY_PATH,
        "columns": {
            "id": ("id", "int"),
            "name": ("name", "str"),
            "operating_system": ("operating_system", "str"),
            "cpu": ("cpu", "str"),
            "computer_type": ("computer_type", "str"),
            "agent_type": ("agent_type", "str"),
            "agent_version": ("agent_version", "str"),
            "ip_addresses": ("ip_addresses", "str"),
            "user_names": ("user_names", "str"),
            "relay_server": ("relay_server", "str"),
            "locked": ("locked", "bool"),
            "last_report_time": ("last_report_time", "datetime", _TIME_FORMAT),
        },
    },
    "fixlets": {
        "endpoint": _QUERY_PATH,
        "columns": {
            "id": ("id", "int"),
            "site_name": ("site_name", "str"),
            "name": ("name", "str"),
            "category": ("category", "str"),
            "source": ("source", "str"),
            "source_id": ("source_id", "str"),
            "source_severity": ("source_severity", "str"),
            "source_release_date": (
                "source_release_date",
                "datetime",
                _DATE_FORMAT,
            ),
            "cve_ids": ("cve_ids", "str"),
            "applicable_computer_count": ("applicable_computer_count", "int"),
        },
    },
    "fixlet_results": {
        "endpoint": _QUERY_PATH,
        "columns": {
            "computer_id": ("computer_id", "int"),
            "computer_name": ("computer_name", "str"),
            "fixlet_id": ("fixlet_id", "int"),
            "fixlet_site_name": ("fixlet_site_name", "str"),
            "fixlet_name": ("fixlet_name", "str"),
            "source_severity": ("source_severity", "str"),
            "first_became_relevant": (
                "first_became_relevant",
                "datetime",
                _TIME_FORMAT,
            ),
            "last_became_relevant": (
                "last_became_relevant",
                "datetime",
                _TIME_FORMAT,
            ),
        },
    },
}


class BigfixCollector(Collector):
    env_prefix = "BIGFIX"
    display_name = "HCL BigFix"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {
        "endpoint": True,
        "username": True,
        "password": True,
        "ca_bundle": False,
        "insecure": False,
    }
    url_config_keys: tuple[str, ...] = ("endpoint",)

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        self._base_url = self._config["endpoint"]
        # Passed on every request rather than set as session.verify: requests
        # lets a REQUESTS_CA_BUNDLE/CURL_CA_BUNDLE env var silently override
        # session.verify, but never an explicit per-request verify=.
        self._verify: bool | str = True

        insecure = self._config.get("insecure", False)
        if isinstance(insecure, str):
            lowered = insecure.strip().lower()
            if lowered not in _TRUE_STRINGS | _FALSE_STRINGS:
                raise ValueError(
                    f"Invalid 'insecure' value {insecure!r}: expected true or false "
                    "(env var BIGFIX_INSECURE)"
                )
            insecure = lowered in _TRUE_STRINGS
        ca_bundle = self._config.get("ca_bundle")

        if insecure and ca_bundle:
            raise ValueError(
                "Config 'insecure' and 'ca_bundle' are mutually exclusive: set one "
                "or the other (env vars BIGFIX_INSECURE / BIGFIX_CA_BUNDLE)"
            )
        if ca_bundle:
            if not Path(ca_bundle).is_file():
                raise ValueError(
                    f"Config 'ca_bundle' file not found: {ca_bundle} "
                    "(env var BIGFIX_CA_BUNDLE)"
                )
            self._verify = str(ca_bundle)
        elif insecure:
            logger.warning(
                "TLS certificate verification disabled for BigFix",
                extra={"source": "bigfix"},
            )
            self._verify = False

    def _authenticate(self) -> None:
        self._session.auth = (self._config["username"], self._config["password"])
        self._session.headers["Accept"] = "application/json"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        query = _QUERIES.get(resource)
        if query is None:
            raise ValueError(f"Unsupported resource '{resource}'")
        unknown = set(kwargs) - {"whose"}
        if unknown:
            raise ValueError(f"Unsupported kwargs for '{resource}': {sorted(unknown)}")

        fields, set_expr = query
        expressions = ", ".join(expr for _, expr in fields)
        relevance = (
            f"({expressions}) of {set_expr.format(whose=kwargs.get('whose', 'true'))}"
        )

        response = self._session.post(
            self._base_url + _QUERY_PATH,
            params={"output": "json"},
            data={"relevance": relevance},
            timeout=_QUERY_TIMEOUT_SECONDS,
            verify=self._verify,
        )
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitedSignal(
                retry_after=float(retry_after) if retry_after else None
            )
        if response.status_code == 401:
            raise UnauthorizedSignal()
        response.raise_for_status()

        names = [name for name, _ in fields]
        return [dict(zip(names, row)) for row in response.json()["result"]], None
