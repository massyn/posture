"""Snyk collector.

Raw ``requests`` against Snyk's REST API v3 (JSON:API envelope) plus one
v1 endpoint that has no REST equivalent (org members) — no vendor SDK.
Auth, retry (429/401/connection-error), and reporting come from the base
Collector.

``organizations`` is a real paginated top-level resource: REST v3's
``links.next`` is already a complete relative path (query string and all),
so the cursor threaded through ``_fetch_page`` *is* that path — the same
shape as ``appomni.py``'s DRF ``next`` URL, just relative instead of
absolute.

``members``, ``projects``, and ``issues`` are per-organisation: Snyk has no
"all orgs" endpoint for any of them, so each fans out one call (``members``,
a bare unpaginated v1 list) or one paginated loop (``projects``/``issues``,
REST v3) per org id across a thread pool — the same per-item fan-out shape
as ``knowbe4.py``'s ``pst_recipients`` (fan out, then paginate internally
per item), not a ``derived_from``/``record_path`` explosion, since org
members/projects/issues are each their own network call rather than data
nested inside the org list response. Org ids are read from ``organizations``
internally unless an ``org_ids`` kwarg is given. ``_org_id`` is injected
client-side into every member/project/issue record (see
``_fetch_all_for_org``).

``targets`` is per-organisation like ``members``/``projects``/``issues``: Snyk
has no "all orgs" targets endpoint, so it's fanned out the same way, with
``_org_id`` injected client-side per record.

``aggregated_issues`` is per-project (``org_id``, ``project_id`` pairs from
``projects``): a v1, ``POST``, unpaginated call to
``/v1/org/{org_id}/project/{project_id}/aggregated-issues``, fanned out the
same way as ``members``/``projects``/``issues``/``targets``. Unlike REST v3
``issues``, this v1 endpoint is vuln-specific but carries materially deeper
data — CVSS vector/score, exploit maturity, fix/patch/upgrade availability,
priority score — so it's additive to ``issues`` rather than a replacement.
``_org_id``/``_project_id`` are injected client-side per record.

Resources: ``organizations``, ``members``, ``projects``, ``issues``,
``targets``, ``aggregated_issues``.

**Caveat:** ``MANIFEST`` column paths below were built from Snyk's public
API reference and a prior in-house extraction script, not a live schema
introspection against a real tenant — same caveat as ``wiz.py`` and
``appomni.py``. Verify field names/nesting against a real tenant's response
before relying on this collector, and correct ``MANIFEST`` if they don't
match.
"""

from __future__ import annotations

import concurrent.futures
import logging
from typing import Any

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger = logging.getLogger("posture.collectors.snyk")

_DEFAULT_BASE_URL = "https://api.snyk.io"
_API_VERSION = "2024-08-25"
_PAGE_LIMIT = 100
_DEFAULT_ORG_FANOUT_MAX_WORKERS = 8

_ORGANIZATIONS_PATH = "/rest/orgs"
_MEMBERS_PATH = "/v1/org/{org_id}/members"
_PROJECTS_PATH = "/rest/orgs/{org_id}/projects"
_ISSUES_PATH = "/rest/orgs/{org_id}/issues"
_TARGETS_PATH = "/rest/orgs/{org_id}/targets"
_AGGREGATED_ISSUES_PATH = "/v1/org/{org_id}/project/{project_id}/aggregated-issues"

MANIFEST: dict[str, dict[str, Any]] = {
    "organizations": {
        "endpoint": _ORGANIZATIONS_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("attributes.name", "str"),
            "slug": ("attributes.slug", "str"),
            "group_id": ("relationships.group.data.id", "str"),
        },
    },
    "members": {
        # Not derived_from "organizations": each org's members are their own
        # (unpaginated, v1) network call, fanned out across a thread pool —
        # not data nested inside the raw org record. _org_id is injected
        # client-side (see _fetch_all_for_org).
        "endpoint": _MEMBERS_PATH,
        "columns": {
            "org_id": ("_org_id", "str"),
            "id": ("id", "str"),
            "username": ("username", "str"),
            "name": ("name", "str"),
            "email": ("email", "str"),
            "role": ("role", "str"),
            "active": ("active", "bool"),
        },
    },
    "projects": {
        # Not derived_from "organizations": each org's projects are their own
        # paginated network call, fanned out across a thread pool. _org_id is
        # injected client-side (see _fetch_all_for_org).
        "endpoint": _PROJECTS_PATH,
        "columns": {
            "org_id": ("_org_id", "str"),
            "id": ("id", "str"),
            "name": ("attributes.name", "str"),
            "type": ("attributes.type", "str"),
            "origin": ("attributes.origin", "str"),
            "status": ("attributes.status", "str"),
            "created": ("attributes.created", "datetime"),
            "target_reference": ("attributes.target_reference", "str"),
            "business_criticality": ("attributes.business_criticality", "json"),
            "environment": ("attributes.environment", "json"),
            "lifecycle": ("attributes.lifecycle", "json"),
            "tags": ("attributes.tags", "json"),
            "target_id": ("relationships.target.data.id", "str"),
        },
    },
    "targets": {
        # Not derived_from "organizations": each org's targets are their own
        # paginated network call, fanned out across a thread pool. _org_id is
        # injected client-side (see _fetch_all_for_org).
        "endpoint": _TARGETS_PATH,
        "columns": {
            "org_id": ("_org_id", "str"),
            "id": ("id", "str"),
            "display_name": ("attributes.display_name", "str"),
            "url": ("attributes.url", "str"),
            "is_private": ("attributes.is_private", "bool"),
            "created_at": ("attributes.created_at", "datetime"),
            "integration_type": (
                "relationships.integration.data.attributes.integration_type",
                "str",
            ),
        },
    },
    "issues": {
        # Not derived_from "organizations": each org's issues are their own
        # paginated network call, fanned out across a thread pool. _org_id is
        # injected client-side (see _fetch_all_for_org).
        "endpoint": _ISSUES_PATH,
        "columns": {
            "org_id": ("_org_id", "str"),
            "id": ("id", "str"),
            "title": ("attributes.title", "str"),
            "type": ("attributes.type", "str"),
            "effective_severity_level": (
                "attributes.effective_severity_level",
                "str",
            ),
            "status": ("attributes.status", "str"),
            "ignored": ("attributes.ignored", "bool"),
            "created_at": ("attributes.created_at", "datetime"),
            "updated_at": ("attributes.updated_at", "datetime"),
            "project_id": ("relationships.scan_item.data.id", "str"),
        },
    },
    "aggregated_issues": {
        # Not derived_from "projects": each project's aggregated issues are
        # their own (POST, v1, unpaginated) network call, fanned out across
        # a thread pool over every (org_id, project_id) pair from
        # "projects". _org_id/_project_id are injected client-side (see
        # _fetch_aggregated_issues_for_project).
        "endpoint": _AGGREGATED_ISSUES_PATH,
        "columns": {
            "org_id": ("_org_id", "str"),
            "project_id": ("_project_id", "str"),
            "id": ("id", "str"),
            "issue_type": ("issueType", "str"),
            "pkg_name": ("pkgName", "str"),
            "pkg_versions": ("pkgVersions", "json"),
            "title": ("issueData.title", "str"),
            "severity": ("issueData.severity", "str"),
            "url": ("issueData.url", "str"),
            "description": ("issueData.description", "str"),
            "cve_ids": ("issueData.identifiers.CVE", "json"),
            "cwe_ids": ("issueData.identifiers.CWE", "json"),
            "exploit_maturity": ("issueData.exploitMaturity", "str"),
            "cvss_v3_vector": ("issueData.CVSSv3", "str"),
            "cvss_score": ("issueData.cvssScore", "float"),
            "publication_time": ("issueData.publicationTime", "datetime"),
            "disclosure_time": ("issueData.disclosureTime", "datetime"),
            "nearest_fixed_in_version": (
                "issueData.nearestFixedInVersion",
                "str",
            ),
            "is_malicious_package": ("issueData.isMaliciousPackage", "bool"),
            "is_patched": ("isPatched", "bool"),
            "is_ignored": ("isIgnored", "bool"),
            "is_upgradable": ("fixInfo.isUpgradable", "bool"),
            "is_pinnable": ("fixInfo.isPinnable", "bool"),
            "is_patchable": ("fixInfo.isPatchable", "bool"),
            "is_fixable": ("fixInfo.isFixable", "bool"),
            "priority_score": ("priorityScore", "int"),
        },
    },
}


class SnykCollector(Collector):
    env_prefix = "SNYK"
    display_name = "Snyk"
    manifest = MANIFEST
    config_keys = {"token": True, "endpoint": False}

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        self._base_url = (self._config.get("endpoint") or _DEFAULT_BASE_URL).rstrip("/")

    def _authenticate(self) -> None:
        self._session.headers["Accept"] = "application/json"
        self._session.headers["Authorization"] = f"token {self._config['token']}"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "organizations":
            return self._fetch_organizations_page(kwargs, cursor)
        if resource == "aggregated_issues":
            return self._fetch_project_fanout_page(kwargs, cursor)
        return self._fetch_org_fanout_page(resource, kwargs, cursor)

    def _fetch_organizations_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            # links.next is already a complete, pre-parameterised relative path.
            response = self._get(self._base_url + cursor)
        else:
            params: dict[str, Any] = {"version": _API_VERSION, "limit": _PAGE_LIMIT}
            params.update(kwargs)
            response = self._get(self._base_url + _ORGANIZATIONS_PATH, params=params)

        payload = response.json()
        records = payload.get("data", []) or []
        next_cursor = (payload.get("links") or {}).get("next")
        return records, next_cursor

    def _fetch_org_fanout_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # entire fan-out already completed on first call

        org_ids = kwargs.get("org_ids")
        if org_ids is None:
            raw_orgs = self._get_raw("organizations", {})
            org_ids = [org["id"] for org in raw_orgs if org.get("id") is not None]
        if not org_ids:
            return [], None

        max_workers = kwargs.get("max_workers", _DEFAULT_ORG_FANOUT_MAX_WORKERS)
        workers = max(1, min(max_workers, len(org_ids)))

        all_records: list[dict[str, Any]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(self._fetch_all_for_org, resource, org_id): org_id
                for org_id in org_ids
            }
            for future in concurrent.futures.as_completed(futures):
                all_records.extend(future.result())

        return all_records, None

    def _fetch_all_for_org(self, resource: str, org_id: str) -> list[dict[str, Any]]:
        if resource == "members":
            records = self._get(
                self._base_url + _MEMBERS_PATH.format(org_id=org_id),
                params={"includeGroupAdmins": "true"},
            ).json()
            if not isinstance(records, list):
                records = []
            for record in records:
                record["_org_id"] = org_id
            return records

        path = {
            "projects": _PROJECTS_PATH,
            "issues": _ISSUES_PATH,
            "targets": _TARGETS_PATH,
        }[resource].format(org_id=org_id)
        records: list[dict[str, Any]] = []
        next_path: str | None = path
        params: dict[str, Any] | None = {
            "version": _API_VERSION,
            "limit": _PAGE_LIMIT,
        }
        while next_path is not None:
            response = self._get(self._base_url + next_path, params=params)
            payload = response.json()
            page_records = payload.get("data", []) or []
            for record in page_records:
                record["_org_id"] = org_id
            records.extend(page_records)
            next_path = (payload.get("links") or {}).get("next")
            params = None  # next_path already carries its own query string
        return records

    def _fetch_project_fanout_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # entire fan-out already completed on first call

        projects = kwargs.get("projects")
        if projects is None:
            raw_projects = self._get_raw("projects", {})
            projects = [
                (project["_org_id"], project["id"])
                for project in raw_projects
                if project.get("_org_id") is not None and project.get("id") is not None
            ]
        if not projects:
            return [], None

        max_workers = kwargs.get("max_workers", _DEFAULT_ORG_FANOUT_MAX_WORKERS)
        workers = max(1, min(max_workers, len(projects)))

        all_records: list[dict[str, Any]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(
                    self._fetch_aggregated_issues_for_project, org_id, project_id
                ): (org_id, project_id)
                for org_id, project_id in projects
            }
            for future in concurrent.futures.as_completed(futures):
                all_records.extend(future.result())

        return all_records, None

    def _fetch_aggregated_issues_for_project(
        self, org_id: str, project_id: str
    ) -> list[dict[str, Any]]:
        response = self._post(
            self._base_url
            + _AGGREGATED_ISSUES_PATH.format(org_id=org_id, project_id=project_id),
            json={"includeDescription": True, "includeIntroducedThrough": True},
        )
        records = response.json().get("issues", []) or []
        for record in records:
            record["_org_id"] = org_id
            record["_project_id"] = project_id
        return records

    def _get(self, url: str, params: dict[str, Any] | None = None) -> Any:
        response = self._session.get(url, params=params, timeout=30)
        return self._check_response(response)

    def _post(self, url: str, json: dict[str, Any]) -> Any:
        response = self._session.post(url, json=json, timeout=30)
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
                extra={"source": "snyk", "status_code": response.status_code},
            )
        response.raise_for_status()
        return response
