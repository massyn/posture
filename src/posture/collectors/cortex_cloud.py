"""Palo Alto Cortex Cloud collector.

Raw ``requests`` against Cortex Cloud's Public API
(``https://api-<fqdn>/public_api/v1/...``) — no vendor SDK. Cortex Cloud
shares its API platform with Cortex XDR/XSIAM, hence the ``x-xdr-*``
header names below. Auth is a static API key + a separate numeric API Key
ID (**not** a single bearer token — Cortex always pairs the two, generated
together under Settings > Configurations > Integrations > API Keys):
``Authorization: <api_key>`` + ``x-xdr-auth-id: <api_key_id>`` ("Standard"
key mode). Cortex also documents an "Advanced" key mode (a per-request
``sha256(api_key + nonce + timestamp)`` hash with ``x-xdr-nonce``/
``x-xdr-timestamp`` headers, to defend against replay) — **not
implemented here**, since it's unverified against a live tenant and
Standard mode is what this collector was built and tested against; add it
if an operator's key is Advanced-only.

``endpoint`` (the tenant's ``api-<fqdn>`` host, e.g.
``https://api-<tenant>.xdr.<region>.paloaltonetworks.com``) is required
config, same "no cross-tenant discovery" shape as Wiz's ``api_endpoint``.

Pagination is offset-based (``request_data.search_from``/``search_to``),
but the response envelope's key casing is **not consistent across
endpoints** — verified live against a real tenant:

- ``assets`` (``POST /public_api/v1/assets``): ``reply.data[]`` /
  ``reply.metadata.total_count``, max page size 1000 (confirmed via a 400
  at 1001 — Cortex's own docs claim 5000, which is wrong).
- ``issues`` (``POST /public_api/v1/issue/search``): ``reply.DATA[]`` /
  ``reply.TOTAL_COUNT``, max page size 100 (confirmed via a 400 above it).

Both stop pagination on a short page rather than trusting the total count,
the same heuristic used elsewhere in posture (e.g. `knowbe4.py` pre-cursor).

Every record on both endpoints comes back with **literal flat keys that
contain dots** (``{"xdm.asset.name": "..."}`` is one key, not a nested
``xdm``/``asset``/``name`` object) — confirmed live. `parse.py`'s manifest
column paths assume dotted-path *traversal* (nested dict lookup), so
`_fetch_page` re-nests every record's keys at fetch time before it's
handed to the pagination scaffold, the same "transform before parse.py
ever sees it" shape `qualys.py`/`tenablesc.py` use for XML.

``assets`` is Cortex's unified multi-cloud/identity/code/image asset
inventory — a single endpoint spans dozens of wildly different asset
types (AWS IAM roles, container images, GitHub repos, software packages,
human identities, ...) under one ``xdm.asset.*`` envelope. Per posture's
allowlist-manifest design (one grain, no generic flattening), `MANIFEST`
here only declares the core ``xdm.asset.*`` fields present on every asset
type; the many type-specific extension namespaces (``xdm.identity.*``,
``xdm.image.*``, ``xdm.code.*``, ``xdm.software_package.*``, etc., live
schema-sampled but not enumerated in full) are out of scope for this
initial cut — revisit as per-type derived resources if a specific
extension namespace turns out to be needed.

``issues`` covers both misconfiguration and vulnerability-style findings
in one feed (Cortex's own terminology, not a posture-invented split) —
unlike Crowdstrike/Qualys's separate vulnerabilities resource, there is no
distinct CVE-only endpoint in the surface explored here.

**Live-verified** (2026-08-19) against a real tenant for both resources'
response envelopes, field names, and page-size limits — a stronger
guarantee than the "not live-verified" caveat most other collectors in
this codebase carry (wiz.py, appomni.py, etc.), though the full
``xdm.asset.*`` type surface obviously wasn't exhaustively sampled.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger = logging.getLogger("posture.collectors.cortex_cloud")

_ASSETS_PATH = "/public_api/v1/assets"
_ISSUES_PATH = "/public_api/v1/issue/search"

_ASSETS_PAGE_SIZE = 1000
_ISSUES_PAGE_SIZE = 100

MANIFEST: dict[str, dict[str, Any]] = {
    "assets": {
        # Core xdm.asset.* fields only — present on every asset type. See
        # module docstring: this endpoint spans dozens of type-specific
        # extension namespaces intentionally left out of this initial cut.
        "endpoint": _ASSETS_PATH,
        "columns": {
            "id": ("xdm.asset.id", "str"),
            "strong_id": ("xdm.asset.strong_id", "str"),
            "name": ("xdm.asset.name", "str"),
            "provider": ("xdm.asset.provider", "str"),
            "realm": ("xdm.asset.realm", "str"),
            "type_id": ("xdm.asset.type.id", "str"),
            "type_name": ("xdm.asset.type.name", "str"),
            "type_class": ("xdm.asset.type.class", "str"),
            "type_category": ("xdm.asset.type.category", "str"),
            "is_resource": ("xdm.asset.type.is_resource", "bool"),
            "cloud_region": ("xdm.asset.cloud.region", "str"),
            "cloud_account_id": ("xdm.asset.cloud.account.id", "str"),
            "cloud_account_name": ("xdm.asset.cloud.account.name", "str"),
            "group_ids": ("xdm.asset.group_ids", "json"),
            "tags": ("xdm.asset.tags", "json"),
            "first_observed": ("xdm.asset.first_observed", "datetime"),
            "last_observed": ("xdm.asset.last_observed", "datetime"),
            "is_inactive": ("xdm.asset.insights.is_inactive", "bool"),
            "is_publicly_accessible": (
                "xdm.asset.insights.is_publicly_accessible",
                "bool",
            ),
            "has_sensitive_data": ("xdm.asset.insights.has_sensitive_data", "bool"),
            "critical_issues": ("xdm.asset.related_issues.critical_issues", "int"),
            "issues_breakdown": ("xdm.asset.related_issues.issues_breakdown", "json"),
            "critical_cases": ("xdm.asset.related_cases.critical_cases", "int"),
            "cases_breakdown": ("xdm.asset.related_cases.cases_breakdown", "json"),
        },
    },
    "issues": {
        "endpoint": _ISSUES_PATH,
        "columns": {
            "id": ("id", "int"),
            "external_id": ("external_id", "str"),
            "name": ("name", "str"),
            "description": ("description", "str"),
            "domain": ("domain", "str"),
            "category": ("category", "str"),
            "severity": ("severity", "str"),
            "type": ("type", "str"),
            "detection_method": ("detection.method", "str"),
            "detection_rule_id": ("detection.rule_id", "str"),
            "status_progress": ("status.progress", "str"),
            "status_resolution_reason": ("status.resolution_reason", "str"),
            "status_resolution_comment": ("status.resolution_comment", "str"),
            "observation_time": ("observation_time", "datetime"),
            "insert_time": ("_insert_time", "datetime"),
            "last_update_timestamp": ("last_update_timestamp", "datetime"),
            "assigned_to": ("assigned_to", "str"),
            "is_excluded": ("is_excluded", "bool"),
            "is_starred": ("is_starred", "bool"),
            "is_excepted": ("is_excepted", "bool"),
            "remediation": ("remediation", "str"),
            "impact": ("impact", "str"),
            "extended_description": ("extended_description", "str"),
            "tags": ("tags", "json"),
            "asset_ids": ("asset_ids", "json"),
            "asset_names": ("asset_names", "json"),
            "asset_types": ("asset_types", "json"),
            "asset_providers": ("asset_providers", "json"),
            "asset_categories": ("asset_categories", "json"),
            "asset_classes": ("asset_classes", "json"),
            "asset_regions": ("asset_regions", "json"),
            "asset_accounts": ("asset_accounts", "json"),
            "asset_group_ids": ("asset_group_ids", "json"),
            "asset_group_names": ("asset_group_names", "json"),
            "case_ids": ("case_ids", "json"),
        },
    },
}


def _nest_dotted_keys(record: dict[str, Any]) -> dict[str, Any]:
    """Turn Cortex's flat ``{"xdm.asset.name": v}`` keys into nested dicts
    (``{"xdm": {"asset": {"name": v}}}``) so parse.py's dotted-path column
    lookup can traverse them. Values are left untouched — a key's own value
    may already be a normal nested dict/list (e.g. ``issues_breakdown``);
    only the key's dots are split."""
    nested: dict[str, Any] = {}
    for key, value in record.items():
        parts = key.split(".")
        node = nested
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value
    return nested


class CortexCloudCollector(Collector):
    env_prefix = "CORTEX"
    display_name = "Palo Alto Cortex Cloud"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {
        "token": True,
        "api_key_id": True,
        "endpoint": True,
    }
    url_config_keys = ("endpoint",)

    def _authenticate(self) -> None:
        self._session.headers["Content-Type"] = "application/json"
        self._session.headers["Authorization"] = self._config["token"]
        self._session.headers["x-xdr-auth-id"] = str(self._config["api_key_id"])

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "issues":
            return self._fetch_issues_page(kwargs, cursor)
        return self._fetch_assets_page(kwargs, cursor)

    def _fetch_assets_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        search_from = cursor if cursor is not None else 0
        search_to = search_from + _ASSETS_PAGE_SIZE
        request_data: dict[str, Any] = {
            "search_from": search_from,
            "search_to": search_to,
        }
        request_data.update(kwargs)

        url = self._config["endpoint"] + _ASSETS_PATH
        reply = self._post(url, {"request_data": request_data}).json()["reply"]
        records = [_nest_dotted_keys(r) for r in reply["data"]]
        next_cursor = search_to if len(records) == _ASSETS_PAGE_SIZE else None
        return records, next_cursor

    def _fetch_issues_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        search_from = cursor if cursor is not None else 0
        search_to = search_from + _ISSUES_PAGE_SIZE
        request_data: dict[str, Any] = {
            "search_from": search_from,
            "search_to": search_to,
        }
        request_data.update(kwargs)

        url = self._config["endpoint"] + _ISSUES_PATH
        reply = self._post(url, {"request_data": request_data}).json()["reply"]
        records = [_nest_dotted_keys(r) for r in reply["DATA"]]
        next_cursor = search_to if len(records) == _ISSUES_PAGE_SIZE else None
        return records, next_cursor

    def _post(self, url: str, body: dict[str, Any]) -> Any:
        response = self._session.post(url, json=body, timeout=30)
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
                extra={"source": "cortex_cloud", "status_code": response.status_code},
            )
        response.raise_for_status()
        return response
