"""SonarCloud collector.

Raw ``requests`` against SonarCloud's Web API (``https://sonarcloud.io/api``)
— no vendor SDK. This targets SonarCloud (the hosted SaaS product), not
SonarQube Server (self-hosted) — the two products have diverging API
surfaces and this collector has not been verified against a self-hosted
instance. Auth is a static user token (``Authorization: Bearer <token>``,
generated under SonarCloud account security settings), the same
"just set the header" shape as Snyk/AppOmni/UpGuard. ``organization`` is
required config: almost every endpoint below is scoped to one organization
key, and SonarCloud has no cross-org "all organizations" listing endpoint a
token could enumerate from — the operator supplies the org key their token
belongs to, the same no-discovery shape as Wiz's ``api_endpoint``.

``organizations`` is a real (if usually single-member) top-level resource —
``/organizations/search?member=true`` returns the orgs the token's user
belongs to, not necessarily just the configured one. ``projects`` is the
other real top-level resource, paginated ``p``/``ps`` with a
``paging.total`` envelope, the same shape ``issues`` uses.

``hotspots``, ``quality_gate_status``, and ``measures`` are all per-project:
SonarCloud has no organization-wide endpoint for any of the three, so each
fans out one call per project key across a thread pool via
``Collector._resumable_fanout`` — the same per-item fan-out shape as
``snyk.py``'s ``members``/``projects``/``issues`` (fan out, then call
per item), not ``derived_from``, since each project's hotspots/quality
gate/measures are their own network call rather than data nested in the
project list response. Project keys are read from ``projects`` internally
unless a ``project_keys`` kwarg is given. ``_project_key`` is injected
client-side into every hotspot/quality-gate/measure record.

``measures`` returns one row per (project, metric) rather than one row per
project — SonarCloud's ``/measures/component`` response nests a list of
``{metric, value}`` pairs under one component, and grain is sacred: one row
per metric observation, not a wide row with a column per metric. The
default metric set (``_DEFAULT_METRIC_KEYS``) covers reliability/security/
maintainability ratings, bug/vulnerability/hotspot/code-smell counts,
coverage, and duplication — overridable via a ``metric_keys`` kwarg.

Resources: ``organizations``, ``projects``, ``issues``, ``hotspots``,
``quality_gate_status``, ``measures``.

**Live-verified against a real organization** (2026-08-24): all six
resources returned correctly-shaped data, including ``hotspots``, whose
field set was the lower-confidence guess at write time.
"""

from __future__ import annotations

import logging
from typing import Any

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger = logging.getLogger("posture.collectors.sonarcloud")

_BASE_URL = "https://sonarcloud.io/api"
_PAGE_SIZE = 100
_DEFAULT_PROJECT_FANOUT_MAX_WORKERS = 8

_ORGANIZATIONS_PATH = "/organizations/search"
_PROJECTS_PATH = "/projects/search"
_ISSUES_PATH = "/issues/search"
_HOTSPOTS_PATH = "/hotspots/search"
_QUALITY_GATE_STATUS_PATH = "/qualitygates/project_status"
_MEASURES_PATH = "/measures/component"

_DEFAULT_METRIC_KEYS = (
    "bugs,vulnerabilities,code_smells,security_hotspots,coverage,"
    "duplicated_lines_density,ncloc,reliability_rating,security_rating,"
    "sqale_rating"
)

MANIFEST: dict[str, dict[str, Any]] = {
    "organizations": {
        "endpoint": _ORGANIZATIONS_PATH,
        "columns": {
            "key": ("key", "str"),
            "name": ("name", "str"),
            "description": ("description", "str"),
            "url": ("url", "str"),
            "avatar": ("avatar", "str"),
            "subscription": ("subscription", "str"),
        },
    },
    "projects": {
        "endpoint": _PROJECTS_PATH,
        "columns": {
            "key": ("key", "str"),
            "name": ("name", "str"),
            "qualifier": ("qualifier", "str"),
            "visibility": ("visibility", "str"),
            "last_analysis_date": ("lastAnalysisDate", "datetime"),
        },
    },
    "issues": {
        "endpoint": _ISSUES_PATH,
        "columns": {
            "key": ("key", "str"),
            "rule": ("rule", "str"),
            "severity": ("severity", "str"),
            "component": ("component", "str"),
            "project": ("project", "str"),
            "line": ("line", "int"),
            "status": ("status", "str"),
            "resolution": ("resolution", "str"),
            "type": ("type", "str"),
            "message": ("message", "str"),
            "effort": ("effort", "str"),
            "tags": ("tags", "json"),
            "author": ("author", "str"),
            "creation_date": ("creationDate", "datetime"),
            "update_date": ("updateDate", "datetime"),
        },
    },
    "hotspots": {
        # Not derived_from "projects": each project's hotspots are their own
        # paginated network call, fanned out across a thread pool.
        # _project_key is injected client-side (see _fetch_for_project).
        "endpoint": _HOTSPOTS_PATH,
        "columns": {
            "project_key": ("_project_key", "str"),
            "key": ("key", "str"),
            "component": ("component", "str"),
            "project": ("project", "str"),
            "security_category": ("securityCategory", "str"),
            "vulnerability_probability": ("vulnerabilityProbability", "str"),
            "status": ("status", "str"),
            "resolution": ("resolution", "str"),
            "line": ("line", "int"),
            "message": ("message", "str"),
            "author": ("author", "str"),
            "creation_date": ("creationDate", "datetime"),
            "update_date": ("updateDate", "datetime"),
        },
    },
    "quality_gate_status": {
        # Not derived_from "projects": each project's quality gate status is
        # its own (unpaginated) network call, fanned out across a thread
        # pool. _project_key is injected client-side (see
        # _fetch_for_project).
        "endpoint": _QUALITY_GATE_STATUS_PATH,
        "columns": {
            "project_key": ("_project_key", "str"),
            "status": ("status", "str"),
            "conditions": ("conditions", "json"),
            "period": ("period", "json"),
        },
    },
    "measures": {
        # Not derived_from "projects": each project's measures are their own
        # (unpaginated) network call, fanned out across a thread pool. One
        # row per (project, metric) — grain is the metric observation, not
        # the project. _project_key is injected client-side (see
        # _fetch_for_project).
        "endpoint": _MEASURES_PATH,
        "columns": {
            "project_key": ("_project_key", "str"),
            "metric": ("metric", "str"),
            "value": ("value", "str"),
            "best_value": ("bestValue", "bool"),
        },
    },
}


class SonarcloudCollector(Collector):
    env_prefix = "SONARCLOUD"
    display_name = "SonarCloud"
    manifest = MANIFEST
    config_keys = {"token": True, "organization": True}

    def _authenticate(self) -> None:
        self._session.headers["Accept"] = "application/json"
        self._session.headers["Authorization"] = f"Bearer {self._config['token']}"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "organizations":
            return self._fetch_paginated_page(
                _ORGANIZATIONS_PATH,
                "organizations",
                {"member": "true"},
                kwargs,
                cursor,
            )
        if resource == "projects":
            return self._fetch_paginated_page(
                _PROJECTS_PATH,
                "components",
                {"organization": self._config["organization"]},
                kwargs,
                cursor,
            )
        if resource == "issues":
            return self._fetch_paginated_page(
                _ISSUES_PATH,
                "issues",
                {"organization": self._config["organization"]},
                kwargs,
                cursor,
            )
        return self._fetch_project_fanout_page(resource, kwargs, cursor)

    def _fetch_paginated_page(
        self,
        path: str,
        list_key: str,
        default_params: dict[str, Any],
        kwargs: dict[str, Any],
        cursor: Any,
    ) -> tuple[list[dict[str, Any]], Any]:
        page_index = cursor if cursor is not None else 1
        params: dict[str, Any] = {**default_params, "p": page_index, "ps": _PAGE_SIZE}
        params.update(kwargs)
        payload = self._get(_BASE_URL + path, params=params).json()
        records = payload.get(list_key, []) or []

        paging = payload.get("paging") or {}
        page_size = paging.get("pageSize", _PAGE_SIZE)
        total = paging.get("total")
        if total is None or page_index * page_size >= total or not records:
            next_cursor = None
        else:
            next_cursor = page_index + 1
        return records, next_cursor

    def _fetch_project_fanout_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # entire fan-out already completed on first call

        project_keys = kwargs.get("project_keys")
        if project_keys is None:
            raw_projects = self._get_raw("projects", {})
            project_keys = [
                project["key"] for project in raw_projects if project.get("key")
            ]
        if not project_keys:
            return [], None

        max_workers = kwargs.get("max_workers", _DEFAULT_PROJECT_FANOUT_MAX_WORKERS)
        workers = max(1, min(max_workers, len(project_keys)))
        metric_keys = kwargs.get("metric_keys", _DEFAULT_METRIC_KEYS)

        all_records = self._resumable_fanout(
            resource,
            project_keys,
            lambda project_key: self._fetch_for_project(
                resource, project_key, metric_keys
            ),
            workers,
        )
        return all_records, None

    def _fetch_for_project(
        self, resource: str, project_key: str, metric_keys: str
    ) -> list[dict[str, Any]]:
        if resource == "hotspots":
            return self._fetch_hotspots_for_project(project_key)
        if resource == "quality_gate_status":
            payload = self._get(
                _BASE_URL + _QUALITY_GATE_STATUS_PATH,
                params={"projectKey": project_key},
            ).json()
            record = payload.get("projectStatus") or {}
            record["_project_key"] = project_key
            return [record]
        # measures
        payload = self._get(
            _BASE_URL + _MEASURES_PATH,
            params={
                "component": project_key,
                "metricKeys": metric_keys,
                "organization": self._config["organization"],
            },
        ).json()
        records = (payload.get("component") or {}).get("measures", []) or []
        for record in records:
            record["_project_key"] = project_key
        return records

    def _fetch_hotspots_for_project(self, project_key: str) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        page_index = 1
        while True:
            payload = self._get(
                _BASE_URL + _HOTSPOTS_PATH,
                params={"projectKey": project_key, "p": page_index, "ps": _PAGE_SIZE},
            ).json()
            page_records = payload.get("hotspots", []) or []
            for record in page_records:
                record["_project_key"] = project_key
            records.extend(page_records)

            paging = payload.get("paging") or {}
            page_size = paging.get("pageSize", _PAGE_SIZE)
            total = paging.get("total")
            if total is None or page_index * page_size >= total or not page_records:
                break
            page_index += 1
        return records

    def _get(self, url: str, params: dict[str, Any] | None = None) -> Any:
        response = self._session.get(url, params=params, timeout=30)
        return self._check_response(response)

    @staticmethod
    def _check_response(response: Any) -> Any:
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitedSignal(
                retry_after=float(retry_after) if retry_after else None
            )
        if response.status_code in (401, 403):
            raise UnauthorizedSignal()
        if response.status_code != 200:
            logger.warning(
                "unexpected status code",
                extra={"source": "sonarcloud", "status_code": response.status_code},
            )
        response.raise_for_status()
        return response
