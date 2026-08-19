"""GitHub collector.

Raw ``requests`` against GitHub's REST API v3 — no vendor SDK. Auth, retry
(429/401/connection-error), and reporting come from the base ``Collector``.
Endpoints and shapes were cross-checked against opensecuritycompliance's
GitHub connector/rules (PyGithub-wrapped org/repo/member/branch listing,
plus raw REST for code scanning, Dependabot, and branch rulesets); this
collector re-implements the same endpoints directly against ``requests``
rather than depending on PyGithub, matching the rest of posture's
collectors. The GraphQL merged-PR report (which needs a separate GitHub
App/JWT auth path) was deliberately left out — PAT auth only.

``organizations`` is the real paginated top-level resource: GitHub's REST
API returns pagination as an RFC 5988 ``Link`` header rather than a JSON
field, so ``requests``' built-in ``response.links`` parsing is used instead
of the JSON-envelope-``next`` shape ``snyk.py``/``appomni.py`` use.

``repositories`` and ``members`` are per-organisation: GitHub has no
"all orgs" endpoint for either, so each fans out one paginated call per org
id across a thread pool — the same per-item fan-out shape as
``snyk.py``'s ``projects``/``issues``. Org logins are read from
``organizations`` internally unless an ``org_logins`` kwarg is given.

``code_scanning_alerts``, ``dependabot_alerts``, and ``branches`` are
per-repository, fanned out the same way from ``repositories``.
``_org`` is injected client-side into every ``repositories``/``members``
record; ``_org``/``_repo`` are injected into every
``code_scanning_alerts``/``dependabot_alerts``/``branches`` record (see
``_fetch_all_for_org``/``_fetch_all_for_repo``).

``branch_protection_rules`` is per-branch: for each (org, repo, branch)
triple from ``branches`` it fans out one call to the branch rulesets
endpoint (``/repos/{owner}/{repo}/rules/branches/{branch}``), which
returns the list of rules actively applicable to that branch (empty list
if none) rather than 404ing on an unprotected branch, unlike the classic
``/branches/{branch}/protection`` endpoint. ``_org``/``_repo``/``_branch``
are injected client-side per record.

Resources: ``organizations``, ``repositories``, ``members``,
``code_scanning_alerts``, ``dependabot_alerts``, ``branches``,
``branch_protection_rules``.
"""

from __future__ import annotations

import concurrent.futures
import logging
import os
from typing import Any

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger = logging.getLogger("posture.collectors.github")

_DEFAULT_BASE_URL = "https://api.github.com"
_API_VERSION = "2022-11-28"
_PAGE_SIZE = 100
_DEFAULT_FANOUT_MAX_WORKERS = 8

_ORGANIZATIONS_PATH = "/user/orgs"
_REPOSITORIES_PATH = "/orgs/{org}/repos"
_MEMBERS_PATH = "/orgs/{org}/members"
_CODE_SCANNING_ALERTS_PATH = "/repos/{full_name}/code-scanning/alerts"
_DEPENDABOT_ALERTS_PATH = "/repos/{full_name}/dependabot/alerts"
_BRANCHES_PATH = "/repos/{full_name}/branches"
_BRANCH_RULES_PATH = "/repos/{full_name}/rules/branches/{branch}"

# resource -> (source_resource, path fanned out per source record)
_ORG_FANOUT: dict[str, tuple[str, str]] = {
    "repositories": ("organizations", _REPOSITORIES_PATH),
    "members": ("organizations", _MEMBERS_PATH),
}
_REPO_FANOUT: dict[str, tuple[str, str]] = {
    "code_scanning_alerts": ("repositories", _CODE_SCANNING_ALERTS_PATH),
    "dependabot_alerts": ("repositories", _DEPENDABOT_ALERTS_PATH),
    "branches": ("repositories", _BRANCHES_PATH),
}

MANIFEST: dict[str, dict[str, Any]] = {
    "organizations": {
        "endpoint": _ORGANIZATIONS_PATH,
        "columns": {
            "id": ("id", "str"),
            "login": ("login", "str"),
            "description": ("description", "str"),
            "url": ("url", "str"),
        },
    },
    "repositories": {
        # Not derived_from "organizations": each org's repos are their own
        # paginated network call, fanned out across a thread pool. _org is
        # injected client-side (see _fetch_all_for_org).
        "endpoint": _REPOSITORIES_PATH,
        "columns": {
            "org": ("_org", "str"),
            "id": ("id", "str"),
            "name": ("name", "str"),
            "full_name": ("full_name", "str"),
            "private": ("private", "bool"),
            "visibility": ("visibility", "str"),
            "default_branch": ("default_branch", "str"),
            "description": ("description", "str"),
            "language": ("language", "str"),
            "archived": ("archived", "bool"),
            "disabled": ("disabled", "bool"),
            "fork": ("fork", "bool"),
            "is_template": ("is_template", "bool"),
            "topics": ("topics", "json"),
            "license_name": ("license.name", "str"),
            "open_issues_count": ("open_issues_count", "int"),
            "stargazers_count": ("stargazers_count", "int"),
            "forks_count": ("forks_count", "int"),
            "created_at": ("created_at", "datetime"),
            "updated_at": ("updated_at", "datetime"),
            "pushed_at": ("pushed_at", "datetime"),
            "html_url": ("html_url", "str"),
        },
    },
    "members": {
        # Not derived_from "organizations": each org's members are their own
        # paginated network call, fanned out across a thread pool. _org is
        # injected client-side (see _fetch_all_for_org).
        "endpoint": _MEMBERS_PATH,
        "columns": {
            "org": ("_org", "str"),
            "id": ("id", "str"),
            "login": ("login", "str"),
            "type": ("type", "str"),
            "site_admin": ("site_admin", "bool"),
            "html_url": ("html_url", "str"),
        },
    },
    "code_scanning_alerts": {
        # Not derived_from "repositories": each repo's alerts are their own
        # paginated network call, fanned out across a thread pool. _org/_repo
        # are injected client-side (see _fetch_all_for_repo).
        "endpoint": _CODE_SCANNING_ALERTS_PATH,
        "columns": {
            "org": ("_org", "str"),
            "repo": ("_repo", "str"),
            "number": ("number", "int"),
            "state": ("state", "str"),
            "rule_id": ("rule.id", "str"),
            "rule_severity": ("rule.severity", "str"),
            "rule_security_severity_level": (
                "rule.security_severity_level",
                "str",
            ),
            "rule_description": ("rule.description", "str"),
            "tool_name": ("tool.name", "str"),
            "tool_version": ("tool.version", "str"),
            "location_path": (
                "most_recent_instance.location.path",
                "str",
            ),
            "location_start_line": (
                "most_recent_instance.location.start_line",
                "int",
            ),
            "location_end_line": (
                "most_recent_instance.location.end_line",
                "int",
            ),
            "message": ("most_recent_instance.message.text", "str"),
            "created_at": ("created_at", "datetime"),
            "updated_at": ("updated_at", "datetime"),
            "fixed_at": ("fixed_at", "datetime"),
            "dismissed_at": ("dismissed_at", "datetime"),
            "dismissed_by": ("dismissed_by.login", "str"),
            "dismissed_reason": ("dismissed_reason", "str"),
            "dismissed_comment": ("dismissed_comment", "str"),
            "html_url": ("html_url", "str"),
        },
    },
    "dependabot_alerts": {
        # Not derived_from "repositories": each repo's alerts are their own
        # paginated network call, fanned out across a thread pool. _org/_repo
        # are injected client-side (see _fetch_all_for_repo).
        "endpoint": _DEPENDABOT_ALERTS_PATH,
        "columns": {
            "org": ("_org", "str"),
            "repo": ("_repo", "str"),
            "number": ("number", "int"),
            "state": ("state", "str"),
            "package_ecosystem": (
                "dependency.package.ecosystem",
                "str",
            ),
            "package_name": ("dependency.package.name", "str"),
            "manifest_path": ("dependency.manifest_path", "str"),
            "scope": ("dependency.scope", "str"),
            "ghsa_id": ("security_advisory.ghsa_id", "str"),
            "cve_id": ("security_advisory.cve_id", "str"),
            "summary": ("security_advisory.summary", "str"),
            "severity": ("security_advisory.severity", "str"),
            "vulnerable_version_range": (
                "security_vulnerability.vulnerable_version_range",
                "str",
            ),
            "first_patched_version": (
                "security_vulnerability.first_patched_version.identifier",
                "str",
            ),
            "created_at": ("created_at", "datetime"),
            "updated_at": ("updated_at", "datetime"),
            "fixed_at": ("fixed_at", "datetime"),
            "dismissed_at": ("dismissed_at", "datetime"),
            "dismissed_by": ("dismissed_by.login", "str"),
            "dismissed_reason": ("dismissed_reason", "str"),
            "dismissed_comment": ("dismissed_comment", "str"),
            "auto_dismissed_at": ("auto_dismissed_at", "datetime"),
            "html_url": ("html_url", "str"),
        },
    },
    "branches": {
        # Not derived_from "repositories": each repo's branches are their own
        # paginated network call, fanned out across a thread pool. _org/_repo
        # are injected client-side (see _fetch_all_for_repo).
        "endpoint": _BRANCHES_PATH,
        "columns": {
            "org": ("_org", "str"),
            "repo": ("_repo", "str"),
            "name": ("name", "str"),
            "protected": ("protected", "bool"),
            "commit_sha": ("commit.sha", "str"),
        },
    },
    "branch_protection_rules": {
        # Not derived_from "branches": each branch's active rules are their
        # own network call, fanned out across a thread pool over every
        # (org, repo, branch) triple from "branches". _org/_repo/_branch are
        # injected client-side (see _fetch_branch_protection_rules).
        "endpoint": _BRANCH_RULES_PATH,
        "columns": {
            "org": ("_org", "str"),
            "repo": ("_repo", "str"),
            "branch": ("_branch", "str"),
            "type": ("type", "str"),
            "ruleset_id": ("ruleset_id", "str"),
            "ruleset_source_type": ("ruleset_source_type", "str"),
            "ruleset_source": ("ruleset_source", "str"),
            "parameters": ("parameters", "json"),
        },
    },
}


class GithubCollector(Collector):
    env_prefix = "GITHUB"
    display_name = "GitHub"
    manifest = MANIFEST
    required_config_keys = ("token",)

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        self._base_url = (
            (config or {}).get("endpoint")
            or os.environ.get("GITHUB_ENDPOINT")
            or _DEFAULT_BASE_URL
        ).rstrip("/")

    def _authenticate(self) -> None:
        self._session.headers["Accept"] = "application/vnd.github+json"
        self._session.headers["Authorization"] = f"Bearer {self._config['token']}"
        self._session.headers["X-GitHub-Api-Version"] = _API_VERSION

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "organizations":
            return self._fetch_organizations_page(kwargs, cursor)
        if resource in _ORG_FANOUT:
            return self._fetch_org_fanout_page(resource, kwargs, cursor)
        if resource in _REPO_FANOUT:
            return self._fetch_repo_fanout_page(resource, kwargs, cursor)
        return self._fetch_branch_protection_page(kwargs, cursor)

    def _fetch_organizations_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            response = self._get(cursor)
        else:
            params = {"per_page": _PAGE_SIZE}
            params.update(kwargs)
            response = self._get(self._base_url + _ORGANIZATIONS_PATH, params=params)

        records = response.json() or []
        next_url = response.links.get("next", {}).get("url")
        return records, next_url

    def _fetch_org_fanout_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # entire fan-out already completed on first call

        org_logins = kwargs.get("org_logins")
        if org_logins is None:
            raw_orgs = self._get_raw("organizations", {})
            org_logins = [org["login"] for org in raw_orgs if org.get("login")]
        if not org_logins:
            return [], None

        path_template = _ORG_FANOUT[resource][1]
        max_workers = kwargs.get("max_workers", _DEFAULT_FANOUT_MAX_WORKERS)
        workers = max(1, min(max_workers, len(org_logins)))

        all_records: list[dict[str, Any]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(self._fetch_all_for_org, path_template, org)
                for org in org_logins
            ]
            for future in concurrent.futures.as_completed(futures):
                all_records.extend(future.result())

        return all_records, None

    def _fetch_all_for_org(self, path_template: str, org: str) -> list[dict[str, Any]]:
        records = self._fetch_all_pages(
            path_template.format(org=org), params={"per_page": _PAGE_SIZE}
        )
        for record in records:
            record["_org"] = org
        return records

    def _fetch_repo_fanout_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # entire fan-out already completed on first call

        repos = kwargs.get("repos")
        if repos is None:
            raw_repos = self._get_raw("repositories", {})
            repos = [
                (repo["_org"], repo["full_name"])
                for repo in raw_repos
                if repo.get("_org") and repo.get("full_name")
            ]
        if not repos:
            return [], None

        path_template = _REPO_FANOUT[resource][1]
        max_workers = kwargs.get("max_workers", _DEFAULT_FANOUT_MAX_WORKERS)
        workers = max(1, min(max_workers, len(repos)))

        all_records: list[dict[str, Any]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(self._fetch_all_for_repo, path_template, org, full_name)
                for org, full_name in repos
            ]
            for future in concurrent.futures.as_completed(futures):
                all_records.extend(future.result())

        return all_records, None

    def _fetch_all_for_repo(
        self, path_template: str, org: str, full_name: str
    ) -> list[dict[str, Any]]:
        records = self._fetch_all_pages(
            path_template.format(full_name=full_name),
            params={"per_page": _PAGE_SIZE},
        )
        repo_name = full_name.split("/", 1)[-1]
        for record in records:
            record["_org"] = org
            record["_repo"] = repo_name
        return records

    def _fetch_branch_protection_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # entire fan-out already completed on first call

        branch_triples = kwargs.get("branch_triples")
        if branch_triples is None:
            raw_branches = self._get_raw("branches", {})
            branch_triples = [
                (branch["_org"], branch["_repo"], branch["name"])
                for branch in raw_branches
                if branch.get("_org") and branch.get("_repo") and branch.get("name")
            ]
        if not branch_triples:
            return [], None

        max_workers = kwargs.get("max_workers", _DEFAULT_FANOUT_MAX_WORKERS)
        workers = max(1, min(max_workers, len(branch_triples)))

        all_records: list[dict[str, Any]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(self._fetch_branch_rules, org, repo, branch)
                for org, repo, branch in branch_triples
            ]
            for future in concurrent.futures.as_completed(futures):
                all_records.extend(future.result())

        return all_records, None

    def _fetch_branch_rules(
        self, org: str, repo: str, branch: str
    ) -> list[dict[str, Any]]:
        full_name = f"{org}/{repo}"
        response = self._get(
            self._base_url
            + _BRANCH_RULES_PATH.format(full_name=full_name, branch=branch)
        )
        records = response.json() or []
        for record in records:
            record["_org"] = org
            record["_repo"] = repo
            record["_branch"] = branch
        return records

    def _fetch_all_pages(
        self, path: str, params: dict[str, Any]
    ) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        next_url: str | None = self._base_url + path
        page_params: dict[str, Any] | None = params
        while next_url is not None:
            response = self._get(next_url, params=page_params)
            records.extend(response.json() or [])
            next_url = response.links.get("next", {}).get("url")
            page_params = None  # next_url already carries its own query string
        return records

    def _get(self, url: str, params: dict[str, Any] | None = None) -> Any:
        response = self._session.get(url, params=params, timeout=30)
        if response.status_code == 429 or (
            response.status_code == 403
            and response.headers.get("X-RateLimit-Remaining") == "0"
        ):
            retry_after = response.headers.get("Retry-After")
            raise RateLimitedSignal(
                retry_after=float(retry_after) if retry_after else None
            )
        if response.status_code in (401, 403):
            raise UnauthorizedSignal()
        if response.status_code != 200:
            logger.warning(
                "unexpected status code",
                extra={"source": "github", "status_code": response.status_code},
            )
        response.raise_for_status()
        return response
