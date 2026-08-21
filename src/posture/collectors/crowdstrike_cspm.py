"""Crowdstrike Falcon Cloud Security (CSPM/Horizon) collector.

Distinct product surface from Falcon endpoint protection (see
``collectors/crowdstrike.py``): a separate OAuth2 client with its own scopes
is issued in the Falcon console for CSPM, hence the separate ``env_prefix``
and collector rather than reusing ``CrowdstrikeCollector``.

Resources: ``iom`` (indicators of misconfiguration), ``cloud_risks``
(CrowdStrike's current unified cloud security findings feed — the successor
to the deprecated per-detection cloud IOA endpoints), ``cloud_asset_inventory``
(discovered cloud resources).

``ioa`` was dropped: CrowdStrike deprecated the standalone cloud
``/detects/*/ioa/*`` endpoints, and the current API reference
(developer.crowdstrike.com) has no confirmed direct successor for
per-detection cloud IOA data — ``cloud_risks`` is the closest current
equivalent, covering both misconfiguration and attack-path risk findings.
Revisit if CrowdStrike documents a dedicated cloud IOA feed.

**Caveat:** ``MANIFEST`` column paths below were built from CrowdStrike's
public Falcon Cloud Security API reference, not a live schema introspection
against a real tenant — same caveat as ``wiz.py``, ``appomni.py``,
``snyk.py``, ``cloudflare.py``, ``dnsimple.py``, ``phriendly_phishing.py``,
and ``vanta.py``. Verify field names/nesting against a real tenant's
response before relying on this collector.
"""

from __future__ import annotations

import logging
from typing import Any

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal
from posture.exceptions import AuthenticationError

logger = logging.getLogger("posture.collectors.crowdstrike_cspm")

_DEFAULT_TOKEN_URL = "https://api.crowdstrike.com/oauth2/token"
_IOM_QUERY_PATH = "/cloud-security-evaluations/queries/ioms/v1"
_IOM_ENTITIES_PATH = "/cloud-security-evaluations/entities/ioms/v1"
_CLOUD_RISKS_PATH = "/cloud-security-risks/combined/cloud-risks/v1"
_ASSETS_QUERY_PATH = "/cloud-security-assets/queries/resources/v1"
_ASSETS_ENTITIES_PATH = "/cloud-security-assets/entities/resources/v1"

_PAGE_LIMIT = 500
# The IOM and cloud-asset-inventory entities endpoints accept at most 100 ids
# per request, so the query-ids page size must not exceed it — unlike
# Falcon's device/ZTA entities endpoints, which take arbitrarily large id
# batches. A larger page size overflows the entities GET's query string
# (hundreds of `ids=` params) and CrowdStrike's API gateway rejects it with
# a 400 Bad Request.
_ENTITIES_PAGE_LIMIT = 100

# CANDIDATE: promote region-discovery (this table + the auth flow that reads
# X-Cs-Region) to base.py — crowdstrike.py needs the identical shape, but
# each collector's __init__ / _authenticate is still small enough that
# duplicating it once more doesn't yet earn a shared primitive.
_REGION_BASE_URLS = {
    "us-1": "https://api.crowdstrike.com",
    "us-2": "https://api.us-2.crowdstrike.com",
    "eu-1": "https://api.eu-1.crowdstrike.com",
    "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
}

MANIFEST: dict[str, dict[str, Any]] = {
    "iom": {
        "endpoint": _IOM_QUERY_PATH,
        "columns": {
            "id": ("id", "str"),
            "cloud_provider": ("cloud_provider", "str"),
            "cloud_scope": ("cloud_scope", "str"),
            "account_id": ("account_id", "str"),
            "account_name": ("account_name", "str"),
            "resource_id": ("resource_id", "str"),
            "resource_type": ("resource_type", "str"),
            "resource_parent": ("resource_parent", "str"),
            "resource_gcrn": ("resource_gcrn", "str"),
            "policy_id": ("policy_id", "str"),
            "policy_name": ("policy_name", "str"),
            "rule_id": ("rule_id", "str"),
            "rule_name": ("rule_name", "str"),
            "severity": ("severity", "str"),
            "status": ("status", "str"),
            "framework": ("framework", "str"),
            "benchmark_name": ("benchmark_name", "str"),
            "created_at": ("created_at", "datetime"),
            "first_detected": ("first_detected", "datetime"),
            "last_detected": ("last_detected", "datetime"),
        },
    },
    "cloud_risks": {
        "endpoint": _CLOUD_RISKS_PATH,
        "columns": {
            "id": ("id", "str"),
            "cloud_provider": ("cloud_provider", "str"),
            "account_id": ("account_id", "str"),
            "account_name": ("account_name", "str"),
            "resource_id": ("resource_id", "str"),
            "resource_type": ("resource_type", "str"),
            "resource_gcrn": ("resource_gcrn", "str"),
            "policy_id": ("policy_id", "str"),
            "risk_type": ("risk_type", "str"),
            "severity": ("severity", "str"),
            "status": ("status", "str"),
            "description": ("description", "str"),
            "first_seen": ("first_seen", "datetime"),
            "last_seen": ("last_seen", "datetime"),
        },
    },
    "cloud_asset_inventory": {
        "endpoint": _ASSETS_QUERY_PATH,
        "columns": {
            "id": ("id", "str"),
            "resource_id": ("resource_id", "str"),
            "resource_name": ("resource_name", "str"),
            "resource_type": ("resource_type", "str"),
            "cloud_provider": ("cloud_provider", "str"),
            "account_id": ("account_id", "str"),
            "region": ("region", "str"),
            "service": ("service", "str"),
            "tags": ("tags", "json"),
            "first_seen": ("first_seen", "datetime"),
            "last_seen": ("last_seen", "datetime"),
        },
    },
}


class CrowdstrikeCspmCollector(Collector):
    env_prefix = "CROWDSTRIKE_CSPM"
    display_name = "Crowdstrike Falcon Cloud Security (CSPM)"
    manifest = MANIFEST
    config_keys = {"client_id": True, "client_secret": True}

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        self._base_url = _REGION_BASE_URLS["us-1"]

    def _authenticate(self) -> None:
        response = self._session.post(
            _DEFAULT_TOKEN_URL,
            data={
                "client_id": self._config["client_id"],
                "client_secret": self._config["client_secret"],
            },
            timeout=30,
        )
        if response.status_code == 401:
            raise AuthenticationError(
                "Crowdstrike CSPM rejected client credentials",
                source="crowdstrike_cspm",
                hint="check CROWDSTRIKE_CSPM_CLIENT_ID / CROWDSTRIKE_CSPM_CLIENT_SECRET",
            )
        if response.status_code not in (200, 201):
            logger.warning(
                "unexpected status code",
                extra={
                    "source": "crowdstrike_cspm",
                    "status_code": response.status_code,
                },
            )
        response.raise_for_status()

        region = response.headers.get("X-Cs-Region")
        if region in _REGION_BASE_URLS:
            self._base_url = _REGION_BASE_URLS[region]

        token = response.json()["access_token"]
        self._session.headers["Authorization"] = f"Bearer {token}"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "iom":
            return self._fetch_entities_page(
                _IOM_QUERY_PATH,
                _IOM_ENTITIES_PATH,
                kwargs,
                cursor,
                query_limit=_ENTITIES_PAGE_LIMIT,
            )
        if resource == "cloud_asset_inventory":
            return self._fetch_entities_page(
                _ASSETS_QUERY_PATH,
                _ASSETS_ENTITIES_PATH,
                kwargs,
                cursor,
                query_limit=_ENTITIES_PAGE_LIMIT,
                pagination_style="after",
            )
        if resource == "cloud_risks":
            return self._fetch_cloud_risks_page(kwargs, cursor)
        raise ValueError(f"Unsupported resource '{resource}'")

    def _fetch_entities_page(
        self,
        query_path: str,
        entities_path: str,
        kwargs: dict[str, Any],
        cursor: Any,
        *,
        query_limit: int = _PAGE_LIMIT,
        pagination_style: str = "offset",
    ) -> tuple[list[dict[str, Any]], Any]:
        ids, next_cursor = self._query_ids(
            query_path, kwargs, cursor, query_limit, pagination_style=pagination_style
        )
        if not ids:
            return [], None

        entities_response = self._session.get(
            self._base_url + entities_path, params={"ids": ids}, timeout=30
        )
        self._raise_for_transient_errors(entities_response)
        entities = entities_response.json().get("resources", [])
        return entities, next_cursor

    def _fetch_cloud_risks_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        params: dict[str, Any] = {"limit": _PAGE_LIMIT}
        if "filter" in kwargs:
            params["filter"] = kwargs["filter"]
        if cursor is not None:
            params["offset"] = cursor

        response = self._session.get(
            self._base_url + _CLOUD_RISKS_PATH, params=params, timeout=30
        )
        self._raise_for_transient_errors(response)
        body = response.json()

        resources = body.get("resources", [])
        pagination = body.get("meta", {}).get("pagination", {})
        total = pagination.get("total", 0)
        offset = pagination.get("offset", 0)
        next_cursor = offset if offset < total else None
        return resources, next_cursor

    def _query_ids(
        self,
        query_path: str,
        kwargs: dict[str, Any],
        cursor: Any,
        query_limit: int = _PAGE_LIMIT,
        *,
        pagination_style: str = "offset",
    ) -> tuple[list[str], Any]:
        params: dict[str, Any] = {"limit": query_limit}
        if "filter" in kwargs:
            params["filter"] = kwargs["filter"]
        if cursor is not None:
            params[pagination_style] = cursor

        response = self._session.get(
            self._base_url + query_path, params=params, timeout=30
        )
        self._raise_for_transient_errors(response)
        body = response.json()

        ids: list[str] = body.get("resources", [])
        meta = body.get("meta", {})
        pagination = meta.get("pagination", {})

        if pagination_style == "after":
            # CrowdStrike caps `offset` pagination at <10,000 and documents
            # `after` as the mechanism for walking a full result set, so
            # this endpoint's `total`/`offset` fields aren't reliable past
            # a small result set. The cursor for the next page is returned
            # as a top-level `meta.next` value (confirmed against a live
            # tenant) — it is not nested under `meta.pagination`.
            next_cursor = meta.get("next") or None
            if not ids:
                next_cursor = None
        else:
            total = pagination.get("total", 0)
            offset = pagination.get("offset", 0)
            next_cursor = offset if offset < total else None
        return ids, next_cursor

    @staticmethod
    def _raise_for_transient_errors(response: Any) -> None:
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitedSignal(
                retry_after=float(retry_after) if retry_after else None
            )
        if response.status_code == 401:
            raise UnauthorizedSignal()
        if response.status_code != 200:
            logger.warning(
                "unexpected status code",
                extra={
                    "source": "crowdstrike_cspm",
                    "status_code": response.status_code,
                },
            )
        response.raise_for_status()
