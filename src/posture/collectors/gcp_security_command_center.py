"""GCP Security Command Center collector.

Raw ``requests`` against the Security Command Center REST API v1
(``https://securitycenter.googleapis.com/v1/organizations/{org}/...``) — no
vendor SDK. Auth is a service-account JWT-bearer exchange **without**
domain-wide delegation (the service account acts as itself; access comes
from an IAM role binding — ``roles/securitycenter.adminViewer`` — on the
organization), via ``_google_oauth.fetch_google_service_account_token``.
``cryptography`` is required for the RS256 signing step, same optional
dependency as the Google Workspace collector
(``pip install "posture[gcp_security_command_center]"``).

``organization_id`` is required config — SCC is an org-level product and
every resource is scoped under ``organizations/{org}``.

Pagination is Google's standard ``pageSize`` / ``pageToken`` /
``nextPageToken``. ``findings`` and ``assets`` wrap each row in a result
envelope (``listFindingsResults[].finding`` / ``listAssetsResults[].asset``
with sibling context) — the manifest reads straight through the wrapper
via dotted paths, so no fetch-time reshaping is needed.

Resources: ``findings``, ``sources``, ``assets``. ``assets`` uses the
legacy asset inventory endpoint (superseded by the newer resource API but
still populated for existing orgs) — a ``filter`` kwarg narrows any of the
three server-side.

**Caveat:** ``MANIFEST`` column paths below were built from the public SCC
v1 REST reference, not a live schema introspection against a real
organization — same caveat as ``wiz.py`` and ``appomni.py``. Verify field
names/nesting against a real org's response before relying on this
collector.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar

from posture.base import Collector
from posture.collectors._google_oauth import (
    fetch_google_service_account_token,
    google_get_json,
)

_BASE_URL = "https://securitycenter.googleapis.com/v1"
_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
_PAGE_SIZE = 1000

_FINDINGS_PATH = "/organizations/{org}/sources/-/findings"
_SOURCES_PATH = "/organizations/{org}/sources"
_ASSETS_PATH = "/organizations/{org}/assets"

# resource -> (path template, envelope list key, per-row unwrap key or None)
_RESOURCES: dict[str, tuple[str, str, str | None]] = {
    "findings": (_FINDINGS_PATH, "listFindingsResults", None),
    "sources": (_SOURCES_PATH, "sources", None),
    "assets": (_ASSETS_PATH, "listAssetsResults", None),
}

MANIFEST: dict[str, dict[str, Any]] = {
    "findings": {
        "endpoint": _FINDINGS_PATH,
        "columns": {
            "name": ("finding.name", "str"),
            "canonical_name": ("finding.canonicalName", "str"),
            "parent": ("finding.parent", "str"),
            "category": ("finding.category", "str"),
            "state": ("finding.state", "str"),
            "severity": ("finding.severity", "str"),
            "finding_class": ("finding.findingClass", "str"),
            "mute": ("finding.mute", "str"),
            "description": ("finding.description", "str"),
            "resource_name": ("finding.resourceName", "str"),
            "external_uri": ("finding.externalUri", "str"),
            "cve_id": ("finding.vulnerability.cve.id", "str"),
            "cvss_base_score": (
                "finding.vulnerability.cve.cvssv3.baseScore",
                "float",
            ),
            "event_time": ("finding.eventTime", "datetime"),
            "create_time": ("finding.createTime", "datetime"),
            "source_properties": ("finding.sourceProperties", "json"),
            "resource_display_name": ("resource.displayName", "str"),
            "resource_type": ("resource.type", "str"),
            "resource_project_display_name": (
                "resource.projectDisplayName",
                "str",
            ),
            "resource_parent_display_name": (
                "resource.parentDisplayName",
                "str",
            ),
        },
    },
    "sources": {
        "endpoint": _SOURCES_PATH,
        "columns": {
            "name": ("name", "str"),
            "canonical_name": ("canonicalName", "str"),
            "display_name": ("displayName", "str"),
            "description": ("description", "str"),
        },
    },
    "assets": {
        "endpoint": _ASSETS_PATH,
        "columns": {
            "name": ("asset.name", "str"),
            "resource_name": (
                "asset.securityCenterProperties.resourceName",
                "str",
            ),
            "resource_type": (
                "asset.securityCenterProperties.resourceType",
                "str",
            ),
            "resource_project": (
                "asset.securityCenterProperties.resourceProject",
                "str",
            ),
            "resource_display_name": (
                "asset.securityCenterProperties.resourceDisplayName",
                "str",
            ),
            "resource_owners": (
                "asset.securityCenterProperties.resourceOwners",
                "json",
            ),
            "create_time": ("asset.createTime", "datetime"),
            "update_time": ("asset.updateTime", "datetime"),
            "resource_properties": ("asset.resourceProperties", "json"),
            "iam_policy": ("asset.iamPolicy.policyBlob", "str"),
        },
    },
}


class GcpSecurityCommandCenterCollector(Collector):
    env_prefix = "GCP_SCC"
    display_name = "GCP Security Command Center"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {
        "service_account_json_path": True,
        "organization_id": True,
    }

    def _authenticate(self) -> None:
        token = fetch_google_service_account_token(
            self._session,
            service_account_json_path=self._config["service_account_json_path"],
            scopes=_SCOPES,
            source="GCP SCC",
        )
        self._session.headers["Authorization"] = f"Bearer {token.access_token}"
        self._token_expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=token.expires_in
        )

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        spec = _RESOURCES.get(resource)
        if spec is None:
            raise ValueError(f"Unsupported resource '{resource}'")
        path_template, list_key, _ = spec

        path = path_template.format(org=self._config["organization_id"])
        params: dict[str, Any] = {"pageSize": _PAGE_SIZE}
        params.update(kwargs)
        if cursor:
            params["pageToken"] = cursor

        body = google_get_json(self._session, _BASE_URL + path, params)
        records = body.get(list_key) or []
        return records, body.get("nextPageToken") or None
