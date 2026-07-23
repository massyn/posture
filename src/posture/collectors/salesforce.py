"""Salesforce collector.

Uses ``simple_salesforce`` (an approved SDK exception — see CLAUDE.md's "no
vendor SDKs unless the API has bespoke machinery the base class can't
generalise" rule; approved here because the alternative is hand-rolling
Salesforce's SOAP login flow, which is exactly the kind of vendor-specific
machinery that rule exists to avoid reimplementing). Auth is username +
password + security token — the same credentials the org's Salesforce admin
hands out, no connected app (client id/secret) required.

Unlike every other collector here, resources aren't hand-written per endpoint:
``salesforce.json`` declares one entry per Salesforce object as a flat
``{field_name: type}`` map, and the manifest — including the SOQL query — is
built from that file at import time. Adding a new object means editing the
JSON, not this module.

Pagination is Salesforce's ``nextRecordsUrl`` scheme, driven via
``Salesforce.query()`` / ``Salesforce.query_more()``.

Resources: one per top-level key in ``salesforce.json``.

Dependencies
------------
    pip install "posture[salesforce]"
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal
from posture.exceptions import AuthenticationError

_DEFAULT_SCHEMA_PATH = Path(__file__).parent / "salesforce.json"


def _load_manifest(schema_path: Path) -> dict[str, dict[str, Any]]:
    tables: dict[str, dict[str, str]] = json.loads(schema_path.read_text())
    manifest: dict[str, dict[str, Any]] = {}
    for table, fields in tables.items():
        query = f"select {','.join(fields)} from {table}"
        manifest[table] = {
            "query": query,
            "columns": {
                field.lower(): (field, dtype) for field, dtype in fields.items()
            },
        }
    return manifest


MANIFEST: dict[str, dict[str, Any]] = _load_manifest(_DEFAULT_SCHEMA_PATH)


class SalesforceCollector(Collector):
    env_prefix = "SALESFORCE"
    manifest = MANIFEST
    required_config_keys = ("username", "password", "token")

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        # None = production (login.salesforce.com); "test" = sandbox
        # (test.salesforce.com); simple_salesforce also accepts a custom My
        # Domain string here for orgs that need one.
        self._domain = (config or {}).get("domain") or os.environ.get(
            "SALESFORCE_DOMAIN"
        )
        self._sf: Any = None

        # Unlike every other collector's manifest (fixed per source), this one
        # is generated from salesforce.json. A caller with a different set of
        # Salesforce objects to collect can point at their own schema file
        # instead of editing the one shipped with posture.
        schema_file = (config or {}).get("schema_file") or os.environ.get(
            "SALESFORCE_SCHEMA_FILE"
        )
        if schema_file:
            self.manifest = _load_manifest(Path(schema_file))

    def _authenticate(self) -> None:
        try:
            from simple_salesforce import Salesforce
        except ImportError as exc:
            raise ImportError(
                "simple_salesforce is required for the Salesforce collector. "
                'Install it with: pip install "posture[salesforce]"'
            ) from exc

        try:
            self._sf = Salesforce(
                username=self._config["username"],
                password=self._config["password"],
                security_token=self._config["token"],
                domain=self._domain,
            )
        except (
            Exception
        ) as exc:  # noqa: BLE001 - simple_salesforce raises its own taxonomy
            raise AuthenticationError(
                "Salesforce rejected the provided username/password/security token",
                source="salesforce",
                hint="check SALESFORCE_USERNAME/PASSWORD/SALESFORCE_TOKEN",
            ) from exc

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        from simple_salesforce.exceptions import (
            SalesforceExpiredSession,
            SalesforceRefusedRequest,
        )

        try:
            if cursor is None:
                result = self._sf.query(self.manifest[resource]["query"])
            else:
                result = self._sf.query_more(cursor, identifier_is_url=True)
        except SalesforceExpiredSession as exc:
            raise UnauthorizedSignal() from exc
        except SalesforceRefusedRequest as exc:
            raise RateLimitedSignal() from exc

        records: list[dict[str, Any]] = result.get("records", [])
        next_cursor = None if result.get("done", True) else result.get("nextRecordsUrl")
        return records, next_cursor
