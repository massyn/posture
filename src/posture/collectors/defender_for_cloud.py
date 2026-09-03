"""Microsoft Defender for Cloud collector.

Raw ``requests`` against the Azure Resource Manager API
(``https://management.azure.com/subscriptions/{id}/providers/
Microsoft.Security/...``) — no vendor SDK. Auth is Azure AD
client-credentials, shared with ``intune.py`` / ``mde.py`` /
``azure_entra.py`` via ``_azure_oauth.py``, just against the ARM scope
(``https://management.azure.com/.default``) instead of Graph's.

``subscription_id`` is required alongside the tenant/client/secret triad —
every ``Microsoft.Security`` resource is scoped to one subscription, and a
posture instance is one snapshot of one subscription (multi-subscription =
multiple instances, per the locked one-instance-per-source decision).

Pagination is ARM's standard ``{"value": [...], "nextLink": "<url>"}``
envelope — ``nextLink`` is a complete, already-parameterised URL (it
carries its own ``api-version`` and ``$skipToken``), fetched verbatim,
the same "cursor is the next URL" shape as ``appomni.py``. Each resource
pins the ``api-version`` its endpoint requires.

Resources: ``secure_scores``, ``secure_score_controls``, ``assessments``,
``sub_assessments``, ``alerts``, ``regulatory_compliance_standards``.

**Caveat:** ``MANIFEST`` column paths below were built from the public
Azure REST API reference for ``Microsoft.Security``, not a live schema
introspection against a real subscription — same caveat as ``wiz.py``,
``appomni.py``, and ``azure_entra.py``. Verify field names/nesting against
a real subscription's response before relying on this collector.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar

from posture.base import Collector
from posture.collectors._azure_oauth import fetch_azure_ad_token, graph_get_json

_ARM_BASE_URL = "https://management.azure.com"
_ARM_SCOPE = "https://management.azure.com/.default"
_SECURITY_PROVIDER = "/providers/Microsoft.Security"

# Each Microsoft.Security resource type is only served under a specific
# api-version — there is no single version that covers all of them.
_API_VERSIONS = {
    "secure_scores": "2020-01-01",
    "secure_score_controls": "2020-01-01",
    "assessments": "2021-06-01",
    "sub_assessments": "2019-01-01-preview",
    "alerts": "2022-01-01",
    "regulatory_compliance_standards": "2019-01-01-preview",
}

_ENDPOINTS = {
    "secure_scores": f"{_SECURITY_PROVIDER}/secureScores",
    "secure_score_controls": f"{_SECURITY_PROVIDER}/secureScoreControls",
    "assessments": f"{_SECURITY_PROVIDER}/assessments",
    "sub_assessments": f"{_SECURITY_PROVIDER}/subAssessments",
    "alerts": f"{_SECURITY_PROVIDER}/alerts",
    "regulatory_compliance_standards": (
        f"{_SECURITY_PROVIDER}/regulatoryComplianceStandards"
    ),
}

MANIFEST: dict[str, dict[str, Any]] = {
    "secure_scores": {
        "endpoint": _ENDPOINTS["secure_scores"],
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "display_name": ("properties.displayName", "str"),
            "current_score": ("properties.score.current", "float"),
            "max_score": ("properties.score.max", "int"),
            "percentage": ("properties.score.percentage", "float"),
            "weight": ("properties.weight", "int"),
        },
    },
    "secure_score_controls": {
        "endpoint": _ENDPOINTS["secure_score_controls"],
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "display_name": ("properties.displayName", "str"),
            "healthy_resource_count": (
                "properties.healthyResourceCount",
                "int",
            ),
            "unhealthy_resource_count": (
                "properties.unhealthyResourceCount",
                "int",
            ),
            "not_applicable_resource_count": (
                "properties.notApplicableResourceCount",
                "int",
            ),
            "current_score": ("properties.score.current", "float"),
            "max_score": ("properties.score.max", "int"),
            "percentage": ("properties.score.percentage", "float"),
            "weight": ("properties.weight", "int"),
            "control_type": ("properties.definition.properties.controlType", "str"),
            "description": (
                "properties.definition.properties.description",
                "str",
            ),
        },
    },
    "assessments": {
        "endpoint": _ENDPOINTS["assessments"],
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "display_name": ("properties.displayName", "str"),
            "status_code": ("properties.status.code", "str"),
            "status_cause": ("properties.status.cause", "str"),
            "status_description": ("properties.status.description", "str"),
            "resource_id": ("properties.resourceDetails.id", "str"),
            "resource_source": ("properties.resourceDetails.source", "str"),
            "severity": ("properties.metadata.severity", "str"),
            "assessment_type": ("properties.metadata.assessmentType", "str"),
            "description": ("properties.metadata.description", "str"),
            "remediation_description": (
                "properties.metadata.remediationDescription",
                "str",
            ),
            "categories": ("properties.metadata.categories", "json"),
        },
    },
    "sub_assessments": {
        "endpoint": _ENDPOINTS["sub_assessments"],
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "display_name": ("properties.displayName", "str"),
            "status_code": ("properties.status.code", "str"),
            "status_severity": ("properties.status.severity", "str"),
            "category": ("properties.category", "str"),
            "description": ("properties.description", "str"),
            "impact": ("properties.impact", "str"),
            "remediation": ("properties.remediation", "str"),
            "time_generated": ("properties.timeGenerated", "datetime"),
            "resource_id": ("properties.resourceDetails.id", "str"),
            "assessed_resource_type": (
                "properties.additionalData.assessedResourceType",
                "str",
            ),
            "additional_data": ("properties.additionalData", "json"),
        },
    },
    "alerts": {
        "endpoint": _ENDPOINTS["alerts"],
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "alert_display_name": ("properties.alertDisplayName", "str"),
            "alert_type": ("properties.alertType", "str"),
            "severity": ("properties.severity", "str"),
            "status": ("properties.status", "str"),
            "intent": ("properties.intent", "str"),
            "description": ("properties.description", "str"),
            "compromised_entity": ("properties.compromisedEntity", "str"),
            "vendor_name": ("properties.vendorName", "str"),
            "product_name": ("properties.productName", "str"),
            "start_time_utc": ("properties.startTimeUtc", "datetime"),
            "end_time_utc": ("properties.endTimeUtc", "datetime"),
            "time_generated_utc": ("properties.timeGeneratedUtc", "datetime"),
            "processing_end_time_utc": (
                "properties.processingEndTimeUtc",
                "datetime",
            ),
            "resource_identifiers": ("properties.resourceIdentifiers", "json"),
            "entities": ("properties.entities", "json"),
            "techniques": ("properties.techniques", "json"),
        },
    },
    "regulatory_compliance_standards": {
        "endpoint": _ENDPOINTS["regulatory_compliance_standards"],
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "state": ("properties.state", "str"),
            "passed_controls": ("properties.passedControls", "int"),
            "failed_controls": ("properties.failedControls", "int"),
            "skipped_controls": ("properties.skippedControls", "int"),
            "unsupported_controls": ("properties.unsupportedControls", "int"),
        },
    },
}


class DefenderForCloudCollector(Collector):
    env_prefix = "DEFENDER_FOR_CLOUD"
    display_name = "Microsoft Defender for Cloud"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {
        "tenant_id": True,
        "client_id": True,
        "client_secret": True,
        "subscription_id": True,
    }

    def _authenticate(self) -> None:
        token = fetch_azure_ad_token(
            self._session,
            tenant_id=self._config["tenant_id"],
            client_id=self._config["client_id"],
            client_secret=self._config["client_secret"],
            scope=_ARM_SCOPE,
            source="Defender for Cloud",
        )
        self._session.headers["Authorization"] = f"Bearer {token.access_token}"
        self._token_expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=token.expires_in
        )

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            # nextLink is a complete URL (own api-version + $skipToken).
            body = graph_get_json(self._session, cursor, None)
            return body.get("value", []) or [], body.get("nextLink")

        endpoint = _ENDPOINTS.get(resource)
        if endpoint is None:
            raise ValueError(f"Unsupported resource '{resource}'")

        url = (
            f"{_ARM_BASE_URL}/subscriptions/{self._config['subscription_id']}{endpoint}"
        )
        params: dict[str, Any] = {"api-version": _API_VERSIONS[resource]}
        params.update(kwargs)
        body = graph_get_json(self._session, url, params)
        return body.get("value", []) or [], body.get("nextLink")
