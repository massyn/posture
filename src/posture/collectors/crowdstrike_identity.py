"""Crowdstrike Falcon Identity Protection (IDP) collector.

Distinct product surface from Falcon endpoint protection (see
``collectors/crowdstrike.py``) and Falcon Cloud Security
(``collectors/crowdstrike_cspm.py``): a separate OAuth2 client with its own
scopes is issued in the Falcon console for Identity Protection, hence the
separate ``env_prefix`` and collector.

Resources: ``entities`` (identities discovered by Identity Protection — the
GraphQL ``entities`` query, CrowdStrike's only public API surface for
identity inventory/risk data) plus derived ``entity_risk_factors``, and
``detections`` (identity-related Falcon alerts, ``product:'idp'`` filtered
via the shared Alerts API v2 — the same query-then-entities shape as
``crowdstrike.py``'s ``hosts``).

Region auto-discovery (``X-Cs-Region``) mirrors ``crowdstrike.py`` and
``crowdstrike_cspm.py`` exactly — flagged as a ``# CANDIDATE`` for
promotion to ``base.py`` rather than promoted now, per the anti-overfitting
rule.

**Caveat:** ``MANIFEST`` column paths and the GraphQL query below were built
from CrowdStrike's public Identity Protection API reference and third-party
connector documentation, not a live schema introspection against a real
tenant — same caveat as ``wiz.py``, ``appomni.py``, ``snyk.py``,
``cloudflare.py``, ``dnsimple.py``, ``phriendly_phishing.py``, and
``vanta.py``. Verify field names/nesting against a real tenant's response
before relying on this collector.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal
from posture.exceptions import AuthenticationError

logger = logging.getLogger("posture.collectors.crowdstrike_identity")

_DEFAULT_TOKEN_URL = "https://api.crowdstrike.com/oauth2/token"
_GRAPHQL_PATH = "/identity-protection/combined/graphql/v1"
_ALERTS_QUERY_PATH = "/alerts/queries/alerts/v2"
_ALERTS_ENTITIES_PATH = "/alerts/entities/alerts/v2"

_PAGE_LIMIT = 500
_DEFAULT_DETECTIONS_FILTER = "product:'idp'"

# CANDIDATE: promote region-discovery (this table + the auth flow that reads
# X-Cs-Region) to base.py — crowdstrike.py and crowdstrike_cspm.py need the
# identical shape, but each collector's __init__ / _authenticate is still
# small enough that duplicating it once more doesn't yet earn a shared
# primitive.
_REGION_BASE_URLS = {
    "us-1": "https://api.crowdstrike.com",
    "us-2": "https://api.us-2.crowdstrike.com",
    "eu-1": "https://api.eu-1.crowdstrike.com",
    "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
}

_ENTITIES_QUERY = """
query Entities($first: Int, $after: Cursor, $types: [EntityType!], $archived: Boolean) {
  entities(first: $first, after: $after, types: $types, archived: $archived, sortKey: PRIMARY_DISPLAY_NAME, sortOrder: ASCENDING) {
    nodes {
      entityId
      primaryDisplayName
      secondaryDisplayName
      type
      riskScore
      riskScoreSeverity
      emailAddresses
      ipAddresses
      riskFactors {
        type
        severity
      }
      accounts {
        ... on ActiveDirectoryAccount {
          samAccountName
          domain
          enabled
          lastSeen
        }
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"""

MANIFEST: dict[str, dict[str, Any]] = {
    "entities": {
        "endpoint": _GRAPHQL_PATH,
        "columns": {
            "entity_id": ("entityId", "str"),
            "primary_display_name": ("primaryDisplayName", "str"),
            "secondary_display_name": ("secondaryDisplayName", "str"),
            "type": ("type", "str"),
            "risk_score": ("riskScore", "int"),
            "risk_score_severity": ("riskScoreSeverity", "str"),
            "email_addresses": ("emailAddresses", "json"),
            "ip_addresses": ("ipAddresses", "json"),
            "accounts": ("accounts", "json"),
        },
    },
    "entity_risk_factors": {
        "derived_from": "entities",
        "record_path": "riskFactors",
        "columns": {
            "entity_id": ("$parent.entityId", "str"),
            "type": ("type", "str"),
            "severity": ("severity", "str"),
        },
    },
    "detections": {
        "endpoint": _ALERTS_QUERY_PATH,
        "default_filter": _DEFAULT_DETECTIONS_FILTER,
        "columns": {
            "id": ("id", "str"),
            "composite_id": ("composite_id", "str"),
            "client_id": ("cid", "str"),
            "product": ("product", "str"),
            "type": ("type", "str"),
            "name": ("name", "str"),
            "description": ("description", "str"),
            "severity": ("severity", "int"),
            "severity_name": ("severity_name", "str"),
            "confidence": ("confidence", "int"),
            "status": ("status", "str"),
            "source_account_name": ("source_account_name", "str"),
            "source_account_domain": ("source_account_domain", "str"),
            "source_endpoint_ip_address": ("source_endpoint_ip_address", "str"),
            "target_account_name": ("target_account_name", "str"),
            "tactic": ("tactic", "str"),
            "technique": ("technique", "str"),
            "created_at": ("created_timestamp", "datetime"),
            "updated_at": ("updated_timestamp", "datetime"),
            "start_time": ("start_time", "datetime"),
            "end_time": ("end_time", "datetime"),
        },
    },
}


class CrowdstrikeIdentityCollector(Collector):
    env_prefix = "CROWDSTRIKE_IDENTITY"
    display_name = "Crowdstrike Falcon Identity Protection"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {"client_id": True, "client_secret": True}

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
                "Crowdstrike Identity Protection rejected client credentials",
                source="crowdstrike_identity",
                hint="check CROWDSTRIKE_IDENTITY_CLIENT_ID / "
                "CROWDSTRIKE_IDENTITY_CLIENT_SECRET",
            )
        if response.status_code not in (200, 201):
            logger.warning(
                "unexpected status code",
                extra={
                    "source": "crowdstrike_identity",
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
        if resource == "entities":
            return self._fetch_entities_page(kwargs, cursor)
        if resource == "detections":
            return self._fetch_detections_page(kwargs, cursor)
        raise ValueError(f"Unsupported resource '{resource}'")

    def _fetch_entities_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        variables = {
            "first": _PAGE_LIMIT,
            "after": cursor,
            "types": kwargs.get("types", ["USER"]),
            "archived": kwargs.get("archived", False),
        }
        response = self._session.post(
            self._base_url + _GRAPHQL_PATH,
            json={"query": _ENTITIES_QUERY, "variables": variables},
            timeout=60,
        )
        self._raise_for_transient_errors(response)
        body = response.json()

        if body.get("errors"):
            raise RuntimeError(
                f"Crowdstrike Identity Protection GraphQL errors: {body['errors']}"
            )

        connection = body["data"]["entities"]
        nodes = connection.get("nodes", [])
        page_info = connection.get("pageInfo", {})
        next_cursor = (
            page_info.get("endCursor") if page_info.get("hasNextPage") else None
        )
        return nodes, next_cursor

    def _fetch_detections_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        composite_ids, next_cursor = self._query_detection_ids(kwargs, cursor)
        if not composite_ids:
            return [], None

        entities_response = self._session.post(
            self._base_url + _ALERTS_ENTITIES_PATH,
            json={"composite_ids": composite_ids},
            timeout=30,
        )
        self._raise_for_transient_errors(entities_response)
        detections = entities_response.json().get("resources", [])
        return detections, next_cursor

    def _query_detection_ids(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[str], Any]:
        params: dict[str, Any] = {
            "filter": kwargs.get("filter", _DEFAULT_DETECTIONS_FILTER),
            "limit": _PAGE_LIMIT,
        }
        if cursor is not None:
            params["offset"] = cursor

        response = self._session.get(
            self._base_url + _ALERTS_QUERY_PATH, params=params, timeout=30
        )
        self._raise_for_transient_errors(response)
        body = response.json()

        composite_ids: list[str] = body.get("resources", [])
        pagination = body.get("meta", {}).get("pagination", {})
        total = pagination.get("total", 0)
        offset = pagination.get("offset", 0)
        next_cursor = offset if offset < total else None
        return composite_ids, next_cursor

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
                    "source": "crowdstrike_identity",
                    "status_code": response.status_code,
                },
            )
        response.raise_for_status()
