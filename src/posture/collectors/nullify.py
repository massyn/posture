"""Nullify collector.

Raw ``requests`` against Nullify's REST API (``https://api.<TENANT>.nullify.ai``),
no vendor SDK. Auth is a static service-account token issued out-of-band in
the tenant dashboard (Configure -> Service Accounts), same "just set the
header" shape as AppOmni/Snyk/UpGuard (``Authorization: Bearer <token>``).
``endpoint`` is required config (the tenant-scoped host — Nullify has no
cross-tenant discovery), same no-discovery shape as Wiz's ``api_endpoint``.

Every request is also scoped by a required ``githubOwnerId`` query parameter
(the GitHub organisation Nullify is connected to) — supplied as
``github_owner_id`` config, appended to every request in ``_fetch_page``
rather than exposed as a per-call kwarg, since it identifies *which tenant
data* to read, not a query-shaping option (the same "who am I" vs. "what do
I want" split the locked kwargs-vs-config decision draws elsewhere).

Pagination is cursor-based: a ``limit`` query param bounds page size, a
``nextToken`` query param carries the cursor forward, and the response
echoes the next cursor back under the same ``nextToken`` key — empty/absent
means done. ``repositories`` hits ``/admin/repositories`` (tenant-wide
inventory); ``sca_events`` and ``sast_events`` hit ``/sca/events`` and
``/sast/events`` (Nullify's own terminology: "code-review" product surface
keeps the ``/sast`` path prefix for backwards compatibility, "dependency
analysis" keeps ``/sca``) — a stream of dependency/code-finding alerts,
suppressions, and auto-remediation updates per repository.

Resources: ``repositories``, ``sca_events``, ``sast_events``.

**This collector replaces a legacy in-house extraction script that was
broken against Nullify's current public API** (verified against
docs.nullify.ai, 2026-08-25 — no live tenant available):

- The legacy script paginated ``sca_events``/``sast_events`` with query
  param ``fromEvent`` and read the next cursor from a response field named
  ``nextEventId``. Nullify's documented pagination contract for both
  endpoints is ``nextToken`` on both the request and the response — neither
  ``fromEvent`` nor ``nextEventId`` appears anywhere in the current API
  reference. The legacy script's loop condition also only checked
  ``'nextEventId' in response`` for ``sca_events``
  (``sast_events``'s loop dropped even the emptiness check) — against the
  real API, that key is simply always absent, so both loops in the legacy
  script would silently stop after one page.
- The legacy script also called ``/sca/counts/severity/latest``. That
  endpoint does not appear anywhere in Nullify's current public API
  reference (checked the dependency-analysis, SAST/code-review, and admin
  pages directly) — it has been dropped here rather than kept as a resource
  that would 404 against every real tenant.

**Caveat:** endpoint paths, auth, and the pagination contract above are
confirmed from Nullify's public docs (docs.nullify.ai). Nullify's API
reference pages embed their response-schema examples in a rendered
component this collector could not extract as plain text, so exact response
field names below are inferred from the endpoints' documented purpose and
cross-referenced against comparable SCA/SAST collectors in this codebase
(``snyk.py``'s ``issues``, ``wiz.py``'s ``vulnerabilityFindings``) rather
than confirmed against a live schema or example payload — a materially
weaker caveat tier than ``wiz.py``/``appomni.py``/etc., which at least had a
public schema reference to build column paths from. Field names in
``MANIFEST`` below **must** be verified against a real tenant's response
before relying on this collector; treat every non-obvious column name as a
guess until then.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger = logging.getLogger("posture.collectors.nullify")

_PAGE_LIMIT = 100

_REPOSITORIES_PATH = "/admin/repositories"
_SCA_EVENTS_PATH = "/sca/events"
_SAST_EVENTS_PATH = "/sast/events"

MANIFEST: dict[str, dict[str, Any]] = {
    "repositories": {
        "endpoint": _REPOSITORIES_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "full_name": ("fullName", "str"),
            "private": ("private", "bool"),
            "default_branch": ("defaultBranch", "str"),
            "provider": ("provider", "str"),
            "last_scanned_at": ("lastScannedAt", "datetime"),
            "created_at": ("createdAt", "datetime"),
            "updated_at": ("updatedAt", "datetime"),
        },
    },
    "sca_events": {
        "endpoint": _SCA_EVENTS_PATH,
        "columns": {
            "id": ("id", "str"),
            "type": ("type", "str"),
            "finding_id": ("findingId", "str"),
            "repository_name": ("repository.name", "str"),
            "repository_full_name": ("repository.fullName", "str"),
            "package_name": ("package.name", "str"),
            "package_ecosystem": ("package.ecosystem", "str"),
            "package_version": ("package.version", "str"),
            "cve_id": ("cve", "str"),
            "severity": ("severity", "str"),
            "status": ("status", "str"),
            "title": ("title", "str"),
            "description": ("description", "str"),
            "created_at": ("createdAt", "datetime"),
        },
    },
    "sast_events": {
        "endpoint": _SAST_EVENTS_PATH,
        "columns": {
            "id": ("id", "str"),
            "type": ("type", "str"),
            "finding_id": ("findingId", "str"),
            "repository_name": ("repository.name", "str"),
            "repository_full_name": ("repository.fullName", "str"),
            "rule_id": ("ruleId", "str"),
            "cwe_id": ("cwe", "str"),
            "severity": ("severity", "str"),
            "status": ("status", "str"),
            "title": ("title", "str"),
            "description": ("description", "str"),
            "file_path": ("filePath", "str"),
            "created_at": ("createdAt", "datetime"),
        },
    },
}

_EVENTS_RESULT_KEY: dict[str, str] = {
    "sca_events": "events",
    "sast_events": "events",
}


class NullifyCollector(Collector):
    env_prefix = "NULLIFY"
    display_name = "Nullify"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {
        "token": True,
        "endpoint": True,
        "github_owner_id": True,
    }
    url_config_keys: tuple[str, ...] = ("endpoint",)

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        self._base_url = self._config["endpoint"]

    def _authenticate(self) -> None:
        self._session.headers["Authorization"] = f"Bearer {self._config['token']}"
        self._session.headers["Accept"] = "application/json"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "repositories":
            return self._fetch_list_page(
                _REPOSITORIES_PATH, "repositories", kwargs, cursor
            )
        if resource in _EVENTS_RESULT_KEY:
            path = _SCA_EVENTS_PATH if resource == "sca_events" else _SAST_EVENTS_PATH
            return self._fetch_list_page(
                path, _EVENTS_RESULT_KEY[resource], kwargs, cursor
            )
        raise ValueError(f"Unsupported resource '{resource}'")

    def _fetch_list_page(
        self, path: str, result_key: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        params: dict[str, Any] = {
            "githubOwnerId": self._config["github_owner_id"],
            "limit": _PAGE_LIMIT,
        }
        if cursor:
            params["nextToken"] = cursor
        params.update(kwargs)

        body = self._get(self._base_url + path, params=params)
        records = body.get(result_key) or []
        next_cursor = body.get("nextToken") or None
        return records, next_cursor

    def _get(self, url: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        response = self._session.get(url, params=params, timeout=60)
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitedSignal(
                retry_after=float(retry_after) if retry_after else None
            )
        if response.status_code in (401, 403):
            raise UnauthorizedSignal()
        response.raise_for_status()
        return response.json()
