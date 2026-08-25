"""Jira collector.

Raw ``requests`` against Jira's REST API — plain REST, no vendor SDK
(the `jira` PyPI package would be an unapproved dependency for no bespoke
benefit here, per the anti-overfitting/dependency guardrails). Supports both
deployment types via ``auth_type`` (config key or ``JIRA_AUTH_TYPE``),
defaulting to ``"cloud"``:

- ``cloud`` (default): email + API token, HTTP basic auth, ``/rest/api/3``.
  Issue search uses the current (post-migration) ``POST /rest/api/3/search/jql``
  endpoint, cursor-paginated via ``nextPageToken`` — Jira Cloud deprecated the
  old ``GET /rest/api/2/search`` for new apps.
- ``server`` (Server/Data Center, self-hosted): a Personal Access Token as a
  bearer token, ``/rest/api/2``. Issue search uses the classic
  ``GET /rest/api/2/search``, paginated via ``startAt``/``maxResults``/``total``.

``endpoint`` (the Jira base URL) is required in both modes, normalized via
``url_config_keys`` the same as every other operator-supplied host.

Resources: ``issues`` (JQL search — ``jql`` kwarg, empty default meaning "every
issue the credential can see", kwargs win per the locked kwargs-override rule)
and ``projects`` (``/rest/api/{2,3}/project/search``, independent paginated
call).

**Custom fields.** Jira custom field ids (``customfield_10001``, ...) aren't
portable across instances/projects — the same id means something different in
every tenant, so they can't be hand-written into ``MANIFEST`` the way standard
fields are. Instead, like ``salesforce.json``/``servicenow.json``, ``jira.json``
declares a ``custom_fields`` map (``{"customfield_10001": ["severity", "str"]}``)
that the operator fills in for their own instance; it's merged onto the
standard `issues` columns at import time, and a different mapping can be
supplied via ``schema_file`` config / ``JIRA_SCHEMA_FILE``, same override
pattern as ServiceNow/Salesforce. Because a stale mapping (a custom field
renamed or deleted in Jira) would otherwise just silently produce an
all-``NaT``/all-``None`` column, every configured custom field id is checked
against ``GET /rest/api/{2,3}/field`` before the first `issues` page is
fetched — a missing id raises loudly instead of collecting quietly-wrong data.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, ClassVar

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal
from posture.exceptions import AuthenticationError

logger = logging.getLogger("posture.collectors.jira")

_DEFAULT_SCHEMA_PATH = Path(__file__).parent / "jira.json"
_PAGE_SIZE = 100
_AUTH_TYPES = ("cloud", "server")

_STANDARD_ISSUE_COLUMNS: dict[str, tuple[str, str]] = {
    "id": ("id", "str"),
    "key": ("key", "str"),
    "summary": ("fields.summary", "str"),
    "issue_type": ("fields.issuetype.name", "str"),
    "status": ("fields.status.name", "str"),
    "priority": ("fields.priority.name", "str"),
    "project_key": ("fields.project.key", "str"),
    "assignee": ("fields.assignee.displayName", "str"),
    "assignee_email": ("fields.assignee.emailAddress", "str"),
    "reporter": ("fields.reporter.displayName", "str"),
    "reporter_email": ("fields.reporter.emailAddress", "str"),
    "labels": ("fields.labels", "json"),
    "resolution": ("fields.resolution.name", "str"),
    "created": ("fields.created", "datetime"),
    "updated": ("fields.updated", "datetime"),
    "resolutiondate": ("fields.resolutiondate", "datetime"),
    "duedate": ("fields.duedate", "datetime"),
}

_PROJECT_COLUMNS: dict[str, tuple[str, str]] = {
    "id": ("id", "str"),
    "key": ("key", "str"),
    "name": ("name", "str"),
    "project_type_key": ("projectTypeKey", "str"),
    "style": ("style", "str"),
    "is_private": ("isPrivate", "bool"),
    "lead": ("lead.displayName", "str"),
}


def _load_manifest(
    schema_path: Path,
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    custom_fields: dict[str, list[str]] = json.loads(schema_path.read_text()).get(
        "custom_fields", {}
    )
    issue_columns = dict(_STANDARD_ISSUE_COLUMNS)
    for field_id, (name, dtype) in custom_fields.items():
        issue_columns[name] = (f"fields.{field_id}", dtype)

    manifest: dict[str, dict[str, Any]] = {
        "issues": {"columns": issue_columns},
        "projects": {"columns": dict(_PROJECT_COLUMNS)},
    }
    return manifest, dict(custom_fields)


MANIFEST, _CUSTOM_FIELDS = _load_manifest(_DEFAULT_SCHEMA_PATH)


def _issue_search_fields(columns: dict[str, tuple[str, str]]) -> list[str]:
    """Jira field names to request on /search — the first path segment under
    "fields." for every declared column (e.g. "status" from
    "fields.status.name", "customfield_10001" from "fields.customfield_10001")."""
    fields: list[str] = []
    for path, _dtype in columns.values():
        if path.startswith("fields."):
            name = path.split(".")[1]
            if name not in fields:
                fields.append(name)
    return fields


class JiraCollector(Collector):
    env_prefix = "JIRA"
    display_name = "Jira"
    manifest = MANIFEST
    url_config_keys = ("endpoint",)
    # auth_type/credential keys are resolved conditionally in
    # _resolve_config (a flat required/optional map can't express "one of
    # these two credential sets", same shape as servicenow.py) — declared
    # here anyway purely so catalog()/generated docs list every key this
    # collector accepts.
    config_keys: ClassVar[dict[str, bool]] = {
        "endpoint": True,
        "auth_type": False,
        "email": False,
        "api_token": False,
        "personal_access_token": False,
        "schema_file": False,
    }

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        self._base_url = self._config["endpoint"]
        self._api_version = "3" if self._config["auth_type"] == "cloud" else "2"
        self._custom_field_ids = dict(_CUSTOM_FIELDS)

        schema_file = (config or {}).get("schema_file") or os.environ.get(
            "JIRA_SCHEMA_FILE"
        )
        if schema_file:
            self.manifest, self._custom_field_ids = _load_manifest(Path(schema_file))

        self._custom_fields_validated = False

    def _resolve_config(self, explicit: dict[str, Any]) -> dict[str, Any]:
        resolved: dict[str, Any] = {"endpoint": self._require(explicit, "endpoint")}
        resolved["endpoint"] = self._normalize_url(resolved["endpoint"])

        auth_type = (
            explicit.get("auth_type") or os.environ.get("JIRA_AUTH_TYPE") or "cloud"
        ).lower()
        if auth_type not in _AUTH_TYPES:
            raise ValueError(
                f"Invalid JIRA_AUTH_TYPE '{auth_type}': must be one of {_AUTH_TYPES}"
            )
        resolved["auth_type"] = auth_type

        credential_keys = (
            ("email", "api_token")
            if auth_type == "cloud"
            else ("personal_access_token",)
        )
        for key in credential_keys:
            resolved[key] = self._require(explicit, key)
        return resolved

    def _require(self, explicit: dict[str, Any], key: str) -> str:
        if key in explicit:
            return explicit[key]
        env_var = f"{self.env_prefix}_{key.upper()}"
        value = os.environ.get(env_var)
        if value is None:
            raise ValueError(
                f"Missing required config '{key}': set it explicitly or via "
                f"env var {env_var}"
            )
        return value

    def _authenticate(self) -> None:
        self._session.headers["Accept"] = "application/json"
        self._session.headers["Content-Type"] = "application/json"

        if self._config["auth_type"] == "server":
            self._session.headers["Authorization"] = (
                f"Bearer {self._config['personal_access_token']}"
            )
            response = self._session.get(
                f"{self._base_url}/rest/api/2/myself", timeout=30
            )
        else:
            self._session.auth = (self._config["email"], self._config["api_token"])
            response = self._session.get(
                f"{self._base_url}/rest/api/3/myself", timeout=30
            )

        if response.status_code == 401:
            raise AuthenticationError(
                "Jira rejected the provided credentials",
                source="jira",
                hint=(
                    "check JIRA_EMAIL/JIRA_API_TOKEN (cloud) or "
                    "JIRA_PERSONAL_ACCESS_TOKEN (server)"
                ),
            )
        response.raise_for_status()

    def _validate_custom_fields(self) -> None:
        if self._custom_fields_validated or not self._custom_field_ids:
            self._custom_fields_validated = True
            return

        response = self._session.get(
            f"{self._base_url}/rest/api/{self._api_version}/field", timeout=30
        )
        response.raise_for_status()
        known_ids = {field["id"] for field in response.json()}

        missing = sorted(set(self._custom_field_ids) - known_ids)
        if missing:
            raise ValueError(
                f"jira.json custom_fields references field id(s) not present on "
                f"this Jira instance: {missing}. Re-check the mapping against "
                f"GET {self._base_url}/rest/api/{self._api_version}/field."
            )
        self._custom_fields_validated = True

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "issues":
            self._validate_custom_fields()
            if self._config["auth_type"] == "cloud":
                return self._fetch_issues_cloud(kwargs, cursor)
            return self._fetch_issues_server(kwargs, cursor)
        if resource == "projects":
            return self._fetch_projects(cursor)
        raise ValueError(f"Unknown resource '{resource}'")

    def _fetch_issues_cloud(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        body: dict[str, Any] = {
            "jql": kwargs.get("jql", ""),
            "maxResults": _PAGE_SIZE,
            "fields": _issue_search_fields(self.manifest["issues"]["columns"]),
        }
        if cursor:
            body["nextPageToken"] = cursor

        response = self._session.post(
            f"{self._base_url}/rest/api/3/search/jql", json=body, timeout=30
        )
        self._raise_for_signal(response)
        response.raise_for_status()

        payload = response.json()
        return payload.get("issues", []), payload.get("nextPageToken")

    def _fetch_issues_server(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        start_at = cursor or 0
        params: dict[str, Any] = {
            "jql": kwargs.get("jql", ""),
            "startAt": start_at,
            "maxResults": _PAGE_SIZE,
            "fields": ",".join(
                _issue_search_fields(self.manifest["issues"]["columns"])
            ),
        }

        response = self._session.get(
            f"{self._base_url}/rest/api/2/search", params=params, timeout=30
        )
        self._raise_for_signal(response)
        response.raise_for_status()

        payload = response.json()
        issues = payload.get("issues", [])
        next_cursor = (
            start_at + _PAGE_SIZE if start_at + len(issues) < payload["total"] else None
        )
        return issues, next_cursor

    def _fetch_projects(self, cursor: Any) -> tuple[list[dict[str, Any]], Any]:
        start_at = cursor or 0
        params = {"startAt": start_at, "maxResults": _PAGE_SIZE}

        response = self._session.get(
            f"{self._base_url}/rest/api/{self._api_version}/project/search",
            params=params,
            timeout=30,
        )
        self._raise_for_signal(response)
        response.raise_for_status()

        payload = response.json()
        projects = payload.get("values", [])
        next_cursor = None if payload.get("isLast", True) else start_at + _PAGE_SIZE
        return projects, next_cursor

    @staticmethod
    def _raise_for_signal(response: Any) -> None:
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitedSignal(
                retry_after=float(retry_after) if retry_after else None
            )
        if response.status_code == 401:
            raise UnauthorizedSignal()
