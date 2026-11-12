"""OWASP Dependency-Track collector.

Raw ``requests`` against a self-hosted Dependency-Track API server
(``<endpoint>/api/v1``), no vendor SDK. Auth is a static API key belonging
to a Dependency-Track team (``X-Api-Key: <key>``); the key carries the
team's permissions, so a read-only team (``VIEW_PORTFOLIO`` and
``VIEW_VULNERABILITY``) is the minimal shape.

Pagination is Dependency-Track's ``offset``/``limit`` query params over a
bare JSON array body, draining until a page comes back short - the scheme
the validated in-house inventory script (Citadel todo 421) uses. The
``X-Total-Count`` response header, when present, only saves the trailing
empty request.

Resources: ``projects``, ``project_components`` and ``project_findings``
(both require projects uuids: one paginated call per project). This is a
deliberately small first cut of the key tables - the inventory (which
component version is in which project) and its vulnerability findings.
Policy violations, services, dependency graphs and the vulnerability
catalogue itself are not collected yet.

kwargs: ``projects`` passes kwargs straight through as query params
(``excludeInactive``, ``onlyRoot``, ``name``...). The two per-project
resources accept ``project_uuids`` (an explicit list, skipping the
``projects`` pull) and pass every other kwarg through to each per-project
call (``onlyOutdated``/``onlyDirect`` for components, ``suppressed`` for
findings), merged over the defaults below - kwargs win.

**Caveat:** column paths were built from Dependency-Track's public OpenAPI
spec and documentation (4.x), not a live schema introspection against a
real server - same caveat tier as ``runzero.py``, ``wiz.py`` and others.
Verify field names/nesting against a real server before relying on this
collector.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

import requests

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger = logging.getLogger("posture.collectors.dependency_track")

_API_PREFIX = "/api/v1"
_PAGE_SIZE = 100
_REQUEST_TIMEOUT = 60

# One paginated drain per project. Dependency-Track is self-hosted with no
# published rate limit, so the ceiling is about not saturating the
# operator's own API server.
_MAX_FANOUT_WORKERS = 5

_ENDPOINTS = {
    "projects": "/project",
    "project_components": "/component/project/{uuid}",
    "project_findings": "/finding/project/{uuid}",
}

# Default query params per per-project resource; caller kwargs override.
# Findings include suppressed ones so the analysis state (and the decision
# to suppress) is visible rather than silently filtered out.
_FANOUT_DEFAULT_PARAMS: dict[str, dict[str, Any]] = {
    "project_components": {},
    "project_findings": {"suppressed": "true"},
}

MANIFEST: dict[str, dict[str, Any]] = {
    "projects": {
        "endpoint": _API_PREFIX + _ENDPOINTS["projects"],
        "columns": {
            "project_uuid": ("uuid", "str"),
            "name": ("name", "str"),
            "version": ("version", "str"),
            "group": ("group", "str"),
            "description": ("description", "str"),
            "classifier": ("classifier", "str"),
            "purl": ("purl", "str"),
            "cpe": ("cpe", "str"),
            "active": ("active", "bool"),
            "inactive_since": ("inactiveSince", "datetime"),
            "is_latest": ("isLatest", "bool"),
            "parent_uuid": ("parent.uuid", "str"),
            "tags": ("tags", "json"),
            "last_bom_import": ("lastBomImport", "datetime"),
            "last_bom_import_format": ("lastBomImportFormat", "str"),
            "last_vulnerability_analysis": ("lastVulnerabilityAnalysis", "datetime"),
            "last_inherited_risk_score": ("lastInheritedRiskScore", "float"),
            "metrics_critical": ("metrics.critical", "int"),
            "metrics_high": ("metrics.high", "int"),
            "metrics_medium": ("metrics.medium", "int"),
            "metrics_low": ("metrics.low", "int"),
            "metrics_unassigned": ("metrics.unassigned", "int"),
            "metrics_vulnerabilities": ("metrics.vulnerabilities", "int"),
            "metrics_components": ("metrics.components", "int"),
            "metrics_vulnerable_components": ("metrics.vulnerableComponents", "int"),
            "metrics_suppressed": ("metrics.suppressed", "int"),
            "metrics_findings_total": ("metrics.findingsTotal", "int"),
            "metrics_findings_audited": ("metrics.findingsAudited", "int"),
            "metrics_policy_violations_total": ("metrics.policyViolationsTotal", "int"),
            "metrics_last_occurrence": ("metrics.lastOccurrence", "datetime"),
        },
    },
    "project_components": {
        # One row per component per project. _project_uuid is injected
        # client-side (see _fetch_fanout_page) rather than read from the
        # response, which doesn't reliably embed the owning project.
        "endpoint": _API_PREFIX + _ENDPOINTS["project_components"],
        "requires": "projects",
        "columns": {
            "project_uuid": ("_project_uuid", "str"),
            "component_uuid": ("uuid", "str"),
            "name": ("name", "str"),
            "version": ("version", "str"),
            "group": ("group", "str"),
            "purl": ("purl", "str"),
            "cpe": ("cpe", "str"),
            "classifier": ("classifier", "str"),
            "scope": ("scope", "str"),
            "is_internal": ("isInternal", "bool"),
            "publisher": ("publisher", "str"),
            "license": ("license", "str"),
            "license_expression": ("licenseExpression", "str"),
            "resolved_license_id": ("resolvedLicense.licenseId", "str"),
            "md5": ("md5", "str"),
            "sha1": ("sha1", "str"),
            "sha256": ("sha256", "str"),
            "latest_version": ("repositoryMeta.latestVersion", "str"),
            "last_inherited_risk_score": ("lastInheritedRiskScore", "float"),
        },
    },
    "project_findings": {
        # One row per vulnerable component x vulnerability per project.
        "endpoint": _API_PREFIX + _ENDPOINTS["project_findings"],
        "requires": "projects",
        "columns": {
            "project_uuid": ("_project_uuid", "str"),
            "component_uuid": ("component.uuid", "str"),
            "component_name": ("component.name", "str"),
            "component_version": ("component.version", "str"),
            "component_group": ("component.group", "str"),
            "component_purl": ("component.purl", "str"),
            "vulnerability_uuid": ("vulnerability.uuid", "str"),
            "vuln_id": ("vulnerability.vulnId", "str"),
            "vulnerability_source": ("vulnerability.source", "str"),
            "title": ("vulnerability.title", "str"),
            "severity": ("vulnerability.severity", "str"),
            "cvss_v2_base_score": ("vulnerability.cvssV2BaseScore", "float"),
            "cvss_v3_base_score": ("vulnerability.cvssV3BaseScore", "float"),
            "epss_score": ("vulnerability.epssScore", "float"),
            "epss_percentile": ("vulnerability.epssPercentile", "float"),
            "cwes": ("vulnerability.cwes", "json"),
            "aliases": ("vulnerability.aliases", "json"),
            "published": ("vulnerability.published", "datetime"),
            "analysis_state": ("analysis.state", "str"),
            "is_suppressed": ("analysis.isSuppressed", "bool"),
            "analyzer_identity": ("attribution.analyzerIdentity", "str"),
            "attributed_on": ("attribution.attributedOn", "datetime"),
            "reference_url": ("attribution.referenceUrl", "str"),
            "matrix": ("matrix", "str"),
        },
    },
}


class DependencyTrackCollector(Collector):
    env_prefix = "DEPENDENCY_TRACK"
    display_name = "OWASP Dependency-Track"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {"api_key": True, "endpoint": True}
    url_config_keys: tuple[str, ...] = ("endpoint",)

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        self._base_url = self._config["endpoint"] + _API_PREFIX

    def _authenticate(self) -> None:
        self._session.headers["X-Api-Key"] = self._config["api_key"]
        self._session.headers["Accept"] = "application/json"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "projects":
            offset = cursor if cursor is not None else 0
            return self._get_page(_ENDPOINTS["projects"], dict(kwargs), offset)
        return self._fetch_fanout_page(resource, kwargs, cursor)

    def _fetch_fanout_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # entire fan-out already completed on first call

        params = {**_FANOUT_DEFAULT_PARAMS[resource], **kwargs}
        project_uuids = params.pop("project_uuids", None)
        if project_uuids is None:
            raw_projects = self._get_raw("projects", {})
            project_uuids = [str(p["uuid"]) for p in raw_projects if p.get("uuid")]
        if not project_uuids:
            return [], None

        path_template = _ENDPOINTS[resource]

        def _fetch_one(project_uuid: str) -> list[dict[str, Any]]:
            path = path_template.format(uuid=project_uuid)
            records: list[dict[str, Any]] = []
            offset: int | None = 0
            try:
                while offset is not None:
                    page, offset = self._get_page(path, dict(params), offset)
                    records.extend(page)
            except requests.exceptions.HTTPError as exc:
                status = exc.response.status_code if exc.response is not None else None
                if status != 404:
                    raise
                # A project deleted since projects was pulled - per-project,
                # not a collection-wide failure.
                logger.info(
                    "%s: project not found (404), skipping",
                    resource,
                    extra={
                        "source": "dependency_track",
                        "resource": resource,
                        "record_id": project_uuid,
                    },
                )
                return []
            for record in records:
                record["_project_uuid"] = project_uuid
            return records

        records = self._resumable_fanout(
            resource, project_uuids, _fetch_one, _MAX_FANOUT_WORKERS
        )
        return records, None

    def _get_page(
        self, path: str, params: dict[str, Any], offset: int
    ) -> tuple[list[dict[str, Any]], int | None]:
        """Fetch one page; return its records and the next offset, or
        ``None`` once the drain is complete."""
        params.update({"offset": offset, "limit": _PAGE_SIZE})
        response = self._session.get(
            self._base_url + path, params=params, timeout=_REQUEST_TIMEOUT
        )
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitedSignal(
                retry_after=float(retry_after) if retry_after else None
            )
        if response.status_code in (401, 403):
            raise UnauthorizedSignal()
        response.raise_for_status()
        records = response.json() or []

        total = response.headers.get("X-Total-Count")
        # Some endpoints (findings on older servers) ignore paging and return
        # everything at once. Only an exactly-full page with more to come
        # continues; asking such a server for page 2 would duplicate rows.
        # X-Total-Count, when present, saves the trailing empty request on
        # an exact multiple of the page size.
        next_offset = offset + _PAGE_SIZE
        if len(records) != _PAGE_SIZE or (
            total is not None and next_offset >= int(total)
        ):
            return records, None
        return records, next_offset
