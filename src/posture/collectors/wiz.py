"""Wiz (CSPM/CNAPP) collector.

Raw ``requests`` against Wiz's single GraphQL endpoint — no vendor SDK. Auth,
retry, pagination, caching, and reporting all come from the base Collector;
this module only knows Wiz's queries and resource manifests.

Resources: ``cloud_security_issues`` (the ``issues`` query — CSPM/CNAPP
findings), ``inventory`` (the ``cloudResources`` query — cloud resource
graph), ``vulnerabilities`` (the ``vulnerabilityFindings`` query).

Auth and API endpoints are tenant-specific and not auto-discoverable the way
Crowdstrike's region is (no equivalent of the ``X-Cs-Region`` header): the
token URL defaults to Wiz's standard Auth0 endpoint, but some tenants are
provisioned on Cognito with a different URL shown in their Wiz console under
Settings -> API, so ``token_url`` is accepted as config for that case. The
GraphQL endpoint (``https://api.<region>.app.wiz.io/graphql``) has no sane
default and is always required.

CANDIDATE for revision: the GraphQL field paths in MANIFEST below were built
from third-party connector documentation (Wiz's own docs were unreachable),
not from a live schema introspection or Wiz's own reference. Field names,
nesting, and query argument shapes should be verified against a real
tenant's response on first use and adjusted here if they don't match.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal
from posture.exceptions import AuthenticationError

logger = logging.getLogger("posture.collectors.wiz")

_DEFAULT_TOKEN_URL = "https://auth.app.wiz.io/oauth/token"
_TOKEN_AUDIENCE = "wiz-api"

_PAGE_LIMIT = 500

_ISSUES_QUERY = """
query IssuesTable($first: Int, $after: String, $filterBy: IssueFilters) {
  issues(first: $first, after: $after, filterBy: $filterBy) {
    nodes {
      id
      status
      severity
      createdAt
      updatedAt
      dueAt
      resolvedAt
      resolutionReason
      entity {
        id
        providerUniqueId
        name
        type
        properties
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"""

_CLOUD_RESOURCES_QUERY = """
query CloudResourceSearch($first: Int, $after: String, $filterBy: CloudResourceFilters) {
  cloudResources(first: $first, after: $after, filterBy: $filterBy) {
    nodes {
      id
      name
      type
      subscriptionId
      subscriptionExternalId
      graphEntity {
        id
        name
        type
        properties
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"""

_VULNERABILITY_FINDINGS_QUERY = """
query VulnerabilityFindings($first: Int, $after: String, $filterBy: VulnerabilityFindingFilters) {
  vulnerabilityFindings(first: $first, after: $after, filterBy: $filterBy) {
    nodes {
      id
      name
      description
      CVEDescription
      vendorSeverity
      score
      exploitabilityScore
      impactScore
      hasExploit
      hasCisaKevExploit
      detectionMethod
      status
      fixedVersion
      firstDetectedAt
      lastDetectedAt
      vulnerableAsset {
        ... on VulnerableAssetBase {
          id
          externalId
          name
          type
          nativeType
          region
          cloudPlatform
          status
          providerUniqueId
          subscriptionId
          subscriptionExternalId
          subscriptionName
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
    "cloud_security_issues": {
        "query": _ISSUES_QUERY,
        "field": "issues",
        "columns": {
            "id": ("id", "str"),
            "status": ("status", "str"),
            "severity": ("severity", "str"),
            "created_at": ("createdAt", "datetime"),
            "updated_at": ("updatedAt", "datetime"),
            "due_at": ("dueAt", "datetime"),
            "resolved_at": ("resolvedAt", "datetime"),
            "resolution_reason": ("resolutionReason", "str"),
            "entity_id": ("entity.id", "str"),
            "entity_provider_unique_id": ("entity.providerUniqueId", "str"),
            "entity_name": ("entity.name", "str"),
            "entity_type": ("entity.type", "str"),
            "entity_properties": ("entity.properties", "json"),
        },
    },
    "inventory": {
        "query": _CLOUD_RESOURCES_QUERY,
        "field": "cloudResources",
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "type": ("type", "str"),
            "subscription_id": ("subscriptionId", "str"),
            "subscription_external_id": ("subscriptionExternalId", "str"),
            "graph_entity_id": ("graphEntity.id", "str"),
            "graph_entity_name": ("graphEntity.name", "str"),
            "graph_entity_type": ("graphEntity.type", "str"),
            "properties": ("graphEntity.properties", "json"),
        },
    },
    "vulnerabilities": {
        "query": _VULNERABILITY_FINDINGS_QUERY,
        "field": "vulnerabilityFindings",
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "description": ("description", "str"),
            "cve_description": ("CVEDescription", "str"),
            "vendor_severity": ("vendorSeverity", "str"),
            "score": ("score", "float"),
            "exploitability_score": ("exploitabilityScore", "float"),
            "impact_score": ("impactScore", "float"),
            "has_exploit": ("hasExploit", "bool"),
            "has_cisa_kev_exploit": ("hasCisaKevExploit", "bool"),
            "detection_method": ("detectionMethod", "str"),
            "status": ("status", "str"),
            "fixed_version": ("fixedVersion", "str"),
            "first_detected_at": ("firstDetectedAt", "datetime"),
            "last_detected_at": ("lastDetectedAt", "datetime"),
            "asset_id": ("vulnerableAsset.id", "str"),
            "asset_external_id": ("vulnerableAsset.externalId", "str"),
            "asset_name": ("vulnerableAsset.name", "str"),
            "asset_type": ("vulnerableAsset.type", "str"),
            "asset_native_type": ("vulnerableAsset.nativeType", "str"),
            "asset_region": ("vulnerableAsset.region", "str"),
            "asset_cloud_platform": ("vulnerableAsset.cloudPlatform", "str"),
            "asset_status": ("vulnerableAsset.status", "str"),
            "asset_provider_unique_id": ("vulnerableAsset.providerUniqueId", "str"),
            "asset_subscription_id": ("vulnerableAsset.subscriptionId", "str"),
            "asset_subscription_external_id": (
                "vulnerableAsset.subscriptionExternalId",
                "str",
            ),
            "asset_subscription_name": ("vulnerableAsset.subscriptionName", "str"),
        },
    },
}


class WizCollector(Collector):
    env_prefix = "WIZ"
    display_name = "Wiz"
    manifest = MANIFEST
    required_config_keys = ("client_id", "client_secret", "api_endpoint")

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._token_url = self._config.get("token_url") or _DEFAULT_TOKEN_URL
        self._api_endpoint = self._config["api_endpoint"]

    def _resolve_config(self, explicit: dict[str, Any]) -> dict[str, Any]:
        resolved = super()._resolve_config(explicit)
        # token_url is optional: most tenants use the shared Auth0 endpoint,
        # only Cognito-provisioned tenants need to override it.
        resolved["token_url"] = explicit.get(
            "token_url", os.environ.get("WIZ_TOKEN_URL")
        )
        return resolved

    def _authenticate(self) -> None:
        response = self._session.post(
            self._token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self._config["client_id"],
                "client_secret": self._config["client_secret"],
                "audience": _TOKEN_AUDIENCE,
            },
            timeout=30,
        )
        if response.status_code == 401:
            raise AuthenticationError(
                "Wiz rejected client credentials",
                source="wiz",
                hint="check WIZ_CLIENT_ID / WIZ_CLIENT_SECRET / WIZ_TOKEN_URL",
            )
        response.raise_for_status()

        token = response.json()["access_token"]
        self._session.headers["Authorization"] = f"Bearer {token}"
        self._session.headers["Content-Type"] = "application/json"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        manifest = MANIFEST.get(resource)
        if manifest is None:
            raise ValueError(f"Unsupported resource '{resource}'")

        variables: dict[str, Any] = {
            "first": _PAGE_LIMIT,
            "after": cursor,
            "filterBy": kwargs.get("filter_by", {}),
        }
        response = self._session.post(
            self._api_endpoint,
            json={"query": manifest["query"], "variables": variables},
            timeout=60,
        )
        self._raise_for_transient_errors(response)
        body = response.json()

        if body.get("errors"):
            raise RuntimeError(
                f"Wiz GraphQL errors for '{resource}': {body['errors']}"
            )

        connection = body["data"][manifest["field"]]
        nodes = connection.get("nodes", [])
        page_info = connection.get("pageInfo", {})
        next_cursor = page_info.get("endCursor") if page_info.get("hasNextPage") else None
        return nodes, next_cursor

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
            # Wiz returns GraphQL validation errors (bad query/variable shape)
            # as 400s with a JSON body describing exactly what's wrong — that
            # detail is far more useful than requests' generic HTTPError, so
            # surface it instead of discarding it via raise_for_status().
            logger.warning(
                "unexpected status code",
                extra={
                    "source": "wiz",
                    "status_code": response.status_code,
                    "body": response.text[:2000],
                },
            )
            raise RuntimeError(
                f"Wiz API returned {response.status_code}: {response.text[:2000]}"
            )
