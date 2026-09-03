"""SecurityScorecard collector.

Raw ``requests`` against SecurityScorecard's REST API
(``https://api.securityscorecard.io``) — no vendor SDK, static token auth
via the ``Authorization: Token <token>`` header (note: ``Token``, not
``Bearer``), the same "just set the header" shape as AppOmni/Snyk.

``portfolios`` is the one top-level resource — a bare ``{"entries": [...]}``
list, no pagination. SecurityScorecard has no "all companies" or "all
factors" endpoint, so:

- ``portfolio_companies`` fans out one ``offset``/``limit`` paginated call
  per portfolio id across a thread pool (``requires: "portfolios"``, ids
  read from ``portfolios`` unless a ``portfolio_ids`` kwarg is given). The
  owning portfolio id is injected client-side as ``_portfolio_id``.
- ``company_factors`` fans out one call per company domain, the domains
  taken from ``portfolio_companies`` (``requires`` it). The domain is
  injected client-side as ``_domain``.

Both are the same per-item fan-out shape as ``cloudflare.py``'s
``dns_records`` — ``requires``, not ``derived_from``, since each is its own
network call rather than data nested in the parent's response.

Resources: ``portfolios``, ``portfolio_companies``, ``company_factors``.

**Caveat:** ``MANIFEST`` column paths below were built from
SecurityScorecard's public API reference, not a live schema introspection
against a real tenant — same caveat as ``wiz.py``, ``appomni.py``,
``snyk.py``, and ``cloudflare.py``. Verify field names/nesting against a
real tenant's response before relying on this collector.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal
from posture.exceptions import AuthenticationError

logger = logging.getLogger("posture.collectors.securityscorecard")

_BASE_URL = "https://api.securityscorecard.io"
_PAGE_SIZE = 100
_DEFAULT_FANOUT_MAX_WORKERS = 8

_PORTFOLIOS_PATH = "/portfolios"
_PORTFOLIO_COMPANIES_PATH = "/portfolios/{portfolio_id}/companies"
_COMPANY_FACTORS_PATH = "/companies/{domain}/factors"

MANIFEST: dict[str, dict[str, Any]] = {
    "portfolios": {
        "endpoint": _PORTFOLIOS_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "description": ("description", "str"),
            "privacy": ("privacy", "str"),
            "created_by": ("created_by", "str"),
        },
    },
    "portfolio_companies": {
        "requires": "portfolios",
        "endpoint": _PORTFOLIO_COMPANIES_PATH,
        "columns": {
            "portfolio_id": ("_portfolio_id", "str"),
            "domain": ("domain", "str"),
            "name": ("name", "str"),
            "score": ("score", "int"),
            "grade": ("grade", "str"),
            "grade_url": ("grade_url", "str"),
            "industry": ("industry", "str"),
            "size": ("size", "str"),
            "last30day_score_change": ("last30day_score_change", "int"),
            "total_issue_count": ("total_issue_count", "int"),
            "created_at": ("created_at", "datetime"),
        },
    },
    "company_factors": {
        "requires": "portfolio_companies",
        "endpoint": _COMPANY_FACTORS_PATH,
        "columns": {
            "domain": ("_domain", "str"),
            "name": ("name", "str"),
            "score": ("score", "int"),
            "grade": ("grade", "str"),
            "issue_summary": ("issue_summary", "json"),
        },
    },
}


class SecurityScorecardCollector(Collector):
    env_prefix = "SECURITYSCORECARD"
    display_name = "SecurityScorecard"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {"token": True}

    def _authenticate(self) -> None:
        self._session.headers["Accept"] = "application/json"
        self._session.headers["Authorization"] = f"Token {self._config['token']}"
        response = self._session.get(f"{_BASE_URL}{_PORTFOLIOS_PATH}", timeout=30)
        if response.status_code in (401, 403):
            raise AuthenticationError(
                "SecurityScorecard rejected the API token",
                source="securityscorecard",
                hint="check SECURITYSCORECARD_TOKEN",
            )

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "portfolios":
            payload = self._get_json(f"{_BASE_URL}{_PORTFOLIOS_PATH}", {})
            return payload.get("entries", []) or [], None
        if resource == "portfolio_companies":
            return self._fetch_fanout_page(
                resource,
                kwargs,
                cursor,
                ids=self._portfolio_ids(kwargs),
                fetch_one=self._fetch_companies_for_portfolio,
            )
        if resource == "company_factors":
            return self._fetch_fanout_page(
                resource,
                kwargs,
                cursor,
                ids=self._company_domains(kwargs),
                fetch_one=self._fetch_factors_for_domain,
            )
        raise ValueError(f"Unsupported resource '{resource}'")

    def _portfolio_ids(self, kwargs: dict[str, Any]) -> list[str]:
        ids = kwargs.get("portfolio_ids")
        if ids is not None:
            return list(ids)
        return [
            row["id"]
            for row in self._get_raw("portfolios", {})
            if row.get("id") is not None
        ]

    def _company_domains(self, kwargs: dict[str, Any]) -> list[str]:
        domains = kwargs.get("domains")
        if domains is not None:
            return list(domains)
        seen: dict[str, None] = {}
        for row in self._get_raw("portfolio_companies", {}):
            domain = row.get("domain")
            if domain and domain not in seen:
                seen[domain] = None
        return list(seen)

    def _fetch_fanout_page(
        self,
        resource: str,
        kwargs: dict[str, Any],
        cursor: Any,
        *,
        ids: list[str],
        fetch_one: Any,
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # whole fan-out completed on the first call
        if not ids:
            return [], None
        max_workers = kwargs.get("max_workers", _DEFAULT_FANOUT_MAX_WORKERS)
        workers = max(1, min(max_workers, len(ids)))
        records = self._resumable_fanout(resource, ids, fetch_one, workers)
        return records, None

    def _fetch_companies_for_portfolio(self, portfolio_id: str) -> list[dict[str, Any]]:
        path = _PORTFOLIO_COMPANIES_PATH.format(portfolio_id=portfolio_id)
        records: list[dict[str, Any]] = []
        offset = 0
        while True:
            payload = self._get_json(
                f"{_BASE_URL}{path}", {"limit": _PAGE_SIZE, "offset": offset}
            )
            entries = payload.get("entries", []) or []
            for entry in entries:
                entry["_portfolio_id"] = portfolio_id
            records.extend(entries)
            if len(entries) < _PAGE_SIZE:
                break
            offset += _PAGE_SIZE
        return records

    def _fetch_factors_for_domain(self, domain: str) -> list[dict[str, Any]]:
        path = _COMPANY_FACTORS_PATH.format(domain=domain)
        payload = self._get_json(f"{_BASE_URL}{path}", {})
        entries = payload.get("entries", []) or []
        for entry in entries:
            entry["_domain"] = domain
        return entries

    def _get_json(self, url: str, params: dict[str, Any]) -> dict[str, Any]:
        response = self._session.get(url, params=params, timeout=30)
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitedSignal(
                retry_after=float(retry_after) if retry_after else None
            )
        if response.status_code in (401, 403):
            raise UnauthorizedSignal()
        if response.status_code == 404:
            # A company with no computed scorecard yet — a confirmed-empty
            # result for that domain, not a failure.
            return {"entries": []}
        if response.status_code != 200:
            logger.warning(
                "unexpected status code",
                extra={
                    "source": "securityscorecard",
                    "status_code": response.status_code,
                },
            )
        response.raise_for_status()
        return response.json()
