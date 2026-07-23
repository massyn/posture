"""ServiceNow collector.

Raw ``requests`` against the Table API (``/api/now/table/{table}``) — plain
REST, no vendor SDK needed. Like ``salesforce.py``, resources aren't
hand-written per endpoint: ``servicenow.json`` declares one entry per table
as a flat ``{field_name: type}`` map, and the manifest (including the
``sysparm_fields`` list) is built from that file at import time. Adding a
new table means editing the JSON, not this module. A caller with a
different set of tables to collect can point at their own schema file via
``schema_file`` config / ``SERVICENOW_SCHEMA_FILE``, same as Salesforce.

Auth supports two modes, chosen by ``auth_type`` (config key or
``SERVICENOW_AUTH_TYPE`` env var), defaulting to ``"oauth2"``:

- ``oauth2`` (default): resource-owner password grant against
  ``/oauth_token.do`` — needs ``client_id``, ``client_secret``, ``username``,
  ``password`` (ServiceNow's OAuth apps are registered per-instance and
  still require a user identity, unlike a pure client-credentials flow).
- ``basic``: HTTP basic auth against the REST API user directly — needs
  only ``username``/``password``.

``instance`` (the ``<instance>`` in ``https://<instance>.service-now.com``)
is required in both modes. Pagination is offset/limit
(``sysparm_offset``/``sysparm_limit``), ending when a page returns fewer
than the limit — the same shape as ``sailpoint.py``. Table-specific
filtering is a caller concern via the ``sysparm_query`` kwarg (ServiceNow's
encoded-query syntax), never a manifest default, per the locked
kwargs-override rule.

**Caveat:** ``servicenow.json``'s table/field selection was built from
ServiceNow's public Table API documentation, not a live schema
introspection against a real instance — same caveat as ``wiz.py`` and
``appomni.py``. Verify field names against a real instance's response
before relying on this collector.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal
from posture.exceptions import AuthenticationError

logger = logging.getLogger("posture.collectors.servicenow")

_DEFAULT_SCHEMA_PATH = Path(__file__).parent / "servicenow.json"
_PAGE_LIMIT = 500
_AUTH_TYPES = ("oauth2", "basic")


def _load_manifest(schema_path: Path) -> dict[str, dict[str, Any]]:
    tables: dict[str, dict[str, str]] = json.loads(schema_path.read_text())
    manifest: dict[str, dict[str, Any]] = {}
    for table, fields in tables.items():
        manifest[table] = {
            "sysparm_fields": ",".join(fields),
            "columns": {
                field.lower(): (field, dtype) for field, dtype in fields.items()
            },
        }
    return manifest


MANIFEST: dict[str, dict[str, Any]] = _load_manifest(_DEFAULT_SCHEMA_PATH)


class ServicenowCollector(Collector):
    env_prefix = "SERVICENOW"
    display_name = "ServiceNow"
    manifest = MANIFEST
    # instance is always required; auth_type/credential keys are resolved
    # conditionally in _resolve_config (base's flat required_config_keys
    # can't express "one of these two credential sets").
    required_config_keys = ("instance",)

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        self._base_url = f"https://{self._config['instance']}.service-now.com"

        schema_file = (config or {}).get("schema_file") or os.environ.get(
            "SERVICENOW_SCHEMA_FILE"
        )
        if schema_file:
            self.manifest = _load_manifest(Path(schema_file))

    def _resolve_config(self, explicit: dict[str, Any]) -> dict[str, Any]:
        resolved: dict[str, Any] = {"instance": self._require(explicit, "instance")}

        auth_type = (
            explicit.get("auth_type")
            or os.environ.get("SERVICENOW_AUTH_TYPE")
            or "oauth2"
        ).lower()
        if auth_type not in _AUTH_TYPES:
            raise ValueError(
                f"Invalid SERVICENOW_AUTH_TYPE '{auth_type}': must be one of {_AUTH_TYPES}"
            )
        resolved["auth_type"] = auth_type

        credential_keys = (
            ("client_id", "client_secret", "username", "password")
            if auth_type == "oauth2"
            else ("username", "password")
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

        if self._config["auth_type"] == "basic":
            self._session.auth = (self._config["username"], self._config["password"])
            return

        response = self._session.post(
            f"{self._base_url}/oauth_token.do",
            data={
                "grant_type": "password",
                "client_id": self._config["client_id"],
                "client_secret": self._config["client_secret"],
                "username": self._config["username"],
                "password": self._config["password"],
            },
            timeout=30,
        )
        if response.status_code == 401:
            raise AuthenticationError(
                "ServiceNow rejected the provided OAuth credentials",
                source="servicenow",
                hint="check SERVICENOW_CLIENT_ID/CLIENT_SECRET/USERNAME/PASSWORD",
            )
        response.raise_for_status()

        token = response.json()["access_token"]
        self._session.headers["Authorization"] = f"Bearer {token}"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        offset = cursor or 0
        params: dict[str, Any] = {
            "sysparm_fields": self.manifest[resource]["sysparm_fields"],
            "sysparm_limit": _PAGE_LIMIT,
            "sysparm_offset": offset,
        }
        params.update(kwargs)

        response = self._session.get(
            f"{self._base_url}/api/now/table/{resource}", params=params, timeout=30
        )
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitedSignal(
                retry_after=float(retry_after) if retry_after else None
            )
        if response.status_code == 401:
            raise UnauthorizedSignal()
        response.raise_for_status()

        records: list[dict[str, Any]] = response.json().get("result", [])
        next_cursor = offset + _PAGE_LIMIT if len(records) == _PAGE_LIMIT else None
        return records, next_cursor
