"""AppOmni collector.

Raw ``requests`` against AppOmni's REST API — no vendor SDK, static bearer
token auth (no OAuth flow: the token is issued out-of-band in the AppOmni
console and passed straight through), same pattern as ``upguard.py``'s
``api_key`` header. The API base URL is tenant-specific
(``https://<instance>.appomni.com``) with no cross-tenant discovery
mechanism, so ``instance`` is required config alongside ``access_token``.

Pagination is DRF-style: each page returns ``{"results": [...], "next":
<full URL or null>}``. ``next`` is already a complete, pre-parameterised
URL, so the cursor threaded through ``_fetch_page`` *is* that URL — no
offset/limit bookkeeping needed once the first page is fetched.
``monitored_services`` is the one exception: it returns a bare JSON list
with no pagination envelope at all.

Resources: ``monitored_services``, ``policies``, ``open_policy_issues``,
``posture_policies``, ``unified_identities``, ``policy_risk_summary``.
``policies`` and ``posture_policies`` hit the same ``/policy/`` endpoint
with different default query filters (reference policies vs.
monitored-service-config policies) — not a derived resource, since each
needs its own network call with its own filter.

**Verified against a live tenant** (2026-08-13): the collector's field
paths for ``monitored_services``, ``policies``/``posture_policies``, and
``open_policy_issues`` were originally built from AppOmni's public API
reference and a prior in-house extraction script, not live schema
introspection, and diverged from the real API in several places (nested
paths that are actually flat, renamed fields, fields that don't exist at
all — e.g. no per-monitored-service ``status``/``instance_url``, no
per-policy ``severity``). ``MANIFEST`` below reflects the corrected,
live-verified field names. If a future tenant/API version drifts again,
re-verify with a real request before trusting these paths — same caveat
as ``wiz.py``.

``policy_risk_summary`` is a per-item fan-out (one ``GET
/policy/{id}/`` per ``posture_policies`` row) because the list endpoint
doesn't return ``rule_type_counts`` or ``open_issues_count`` — only the
single-object detail view does. This is what lets you compare "rules
evaluated" against "rules currently failing" per policy, i.e. tell
whether a policy/rule-set is well-covered vs. mostly broken.
"""

from __future__ import annotations

import concurrent.futures
import logging
from typing import Any

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger = logging.getLogger("posture.collectors.appomni")

_MONITORED_SERVICES_PATH = "/api/v1/core/monitoredservice"
_POLICY_PATH = "/api/v1/core/policy/"
_POLICY_DETAIL_PATH = "/api/v1/core/policy/{id}/"
_OPEN_POLICY_ISSUES_PATH = "/api/v1/core/ruleevent/"
_UNIFIED_IDENTITIES_PATH = "/api/v1/core/unifiedidentity/"

_POLICY_RISK_SUMMARY_MAX_WORKERS = 10

_RISK_LEVEL_NAMES = ("Informational", "Low", "Medium", "High", "Critical")

_RESOURCE_PATHS = {
    "monitored_services": _MONITORED_SERVICES_PATH,
    "policies": _POLICY_PATH,
    "open_policy_issues": _OPEN_POLICY_ISSUES_PATH,
    "posture_policies": _POLICY_PATH,
    "unified_identities": _UNIFIED_IDENTITIES_PATH,
}

# Default query params per resource, mirroring the prior extraction
# script's hardcoded query strings. kwargs always win over these when a
# key collides (locked decision 5 in ARCHITECTURE.md).
_RESOURCE_DEFAULT_PARAMS: dict[str, dict[str, Any]] = {
    "policies": {"limit": 25, "offset": 0, "is_reference": "true"},
    "posture_policies": {"filter.policyType": "monitored_service_config"},
    "unified_identities": {"ordering": "-num_users_linked", "limit": 50},
}

MANIFEST: dict[str, dict[str, Any]] = {
    "monitored_services": {
        # instance_url and status don't exist on this endpoint (confirmed
        # against a live tenant) — dropped. app_type/updated were nested
        # under different real field names (service_type/modified). status
        # is replaced by the raw connectivity booleans the API actually
        # returns, plus `score` (AppOmni's own per-service risk score).
        "endpoint": _MONITORED_SERVICES_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "app_type": ("service_type", "str"),
            "score": ("score", "int"),
            "integration_connected": ("integration_connected", "bool"),
            "has_errors": ("has_errors", "bool"),
            "has_warnings": ("has_warnings", "bool"),
            "is_archived": ("is_archived", "bool"),
            "created": ("created", "datetime"),
            "updated": ("modified", "datetime"),
        },
    },
    "policies": {
        # policy_type/enabled/updated were nested under different real field
        # names (policy_type/active/modified). severity doesn't exist on
        # this endpoint — dropped; real risk scoring lives in
        # policy_risk_summary instead (see MANIFEST comment there).
        "endpoint": _POLICY_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "description": ("description", "str"),
            "policy_type": ("policy_type", "str"),
            "is_reference": ("is_reference", "bool"),
            "enabled": ("active", "bool"),
            "created": ("created", "datetime"),
            "updated": ("modified", "datetime"),
        },
    },
    "open_policy_issues": {
        # This endpoint's fields are flat (DRF `source__field`-style column
        # names), not nested objects — confirmed against a live tenant and
        # its own OPTIONS metadata: "Monitored Service, policy, and rule PKs
        # are returned, no object data for any is included in this viewset
        # result". There is no `severity` field; `risk_score` is the closest
        # available signal. There is no monitored-service name field either
        # (only the `service_org_id` PK), so `monitored_service_name` is
        # resolved client-side against `monitored_services` and injected as
        # `_monitored_service_name` (see `_fetch_page`).
        "endpoint": _OPEN_POLICY_ISSUES_PATH,
        "columns": {
            "id": ("id", "str"),
            "policy_id": ("policy_id", "str"),
            "policy_name": ("policy__name", "str"),
            "severity": ("risk_score", "str"),
            "status": ("status", "str"),
            "monitored_service_id": ("service_org_id", "str"),
            "monitored_service_name": ("_monitored_service_name", "str"),
            "rule_id": ("rule_id", "str"),
            "rule_name": ("rule__name", "str"),
            "rule_posture_category": ("rule__rule_posture_category", "str"),
            "rule_service_specific_category": ("rule__service_specific_category", "str"),
            "detected_at": ("created", "datetime"),
            "resolved_at": ("closed_on", "datetime"),
        },
    },
    "posture_policies": {
        "endpoint": _POLICY_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "description": ("description", "str"),
            "policy_type": ("policy_type", "str"),
            "enabled": ("active", "bool"),
            "created": ("created", "datetime"),
            "updated": ("modified", "datetime"),
        },
    },
    "policy_risk_summary": {
        # Fan-out resource: one GET /policy/{id}/ per posture_policies row,
        # because rule_type_counts/open_issues_count only exist on the
        # single-object detail view, not the /policy/ list endpoint. Lets
        # you compute a per-policy coverage ratio: open_issues_count vs.
        # total rules evaluated (sum of rule_type_counts[*].rules) — the
        # "how good is this rule set" signal the raw issues feed can't give
        # you on its own. risk_level_* counts are pulled out of
        # risk_statistics.risk_levels (a list keyed by name, not a dotted
        # path) and injected client-side (see _fetch_policy_risk_summary).
        "endpoint": _POLICY_DETAIL_PATH,
        "columns": {
            "policy_id": ("id", "str"),
            "policy_name": ("name", "str"),
            "policy_type": ("policy_type", "str"),
            "monitored_service_ids": ("monitored_services", "json"),
            "active": ("active", "bool"),
            "open_issues_count": ("open_issues_count", "int"),
            "total_rules_count": ("_total_rules_count", "int"),
            "risk_score": ("_risk_score", "int"),
            "risk_informational_count": ("_risk_informational_count", "int"),
            "risk_low_count": ("_risk_low_count", "int"),
            "risk_medium_count": ("_risk_medium_count", "int"),
            "risk_high_count": ("_risk_high_count", "int"),
            "risk_critical_count": ("_risk_critical_count", "int"),
            "last_completed_scan": ("last_completed_scan", "datetime"),
            "last_policy_assessment_status": ("last_policy_assessment_status", "str"),
        },
    },
    "unified_identities": {
        "endpoint": _UNIFIED_IDENTITIES_PATH,
        "columns": {
            "id": ("id", "str"),
            "name": ("name", "str"),
            "email": ("email", "str"),
            "identity_type": ("identity_type", "str"),
            "num_users_linked": ("num_users_linked", "int"),
            "risk_score": ("risk_score", "float"),
            "created": ("created", "datetime"),
            "updated": ("updated", "datetime"),
        },
    },
}


class AppOmniCollector(Collector):
    env_prefix = "APPOMNI"
    display_name = "AppOmni"
    manifest = MANIFEST
    required_config_keys = ("access_token", "instance")

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        self._base_url = f"https://{self._config['instance']}.appomni.com"
        self._service_org_names: dict[Any, str] | None = None

    def _authenticate(self) -> None:
        self._session.headers["Accept"] = "application/json"
        self._session.headers["Authorization"] = (
            f"Bearer {self._config['access_token']}"
        )

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "policy_risk_summary":
            return self._fetch_policy_risk_summary(kwargs, cursor)

        if cursor is not None:
            # `next` is already a complete, pre-parameterised URL.
            response = self._get(cursor)
        else:
            path = _RESOURCE_PATHS[resource]
            params = dict(_RESOURCE_DEFAULT_PARAMS.get(resource, {}))
            params.update(kwargs)
            response = self._get(self._base_url + path, params=params)

        payload = response.json()
        if isinstance(payload, list):
            # monitored_services: no pagination envelope at all.
            return payload, None

        records = payload.get("results", []) or []
        next_cursor = payload.get("next")

        if resource == "open_policy_issues":
            names = self._get_service_org_names()
            for record in records:
                record["_monitored_service_name"] = names.get(
                    record.get("service_org_id")
                )

        return records, next_cursor

    def _fetch_policy_risk_summary(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # entire fan-out already completed on first call

        policy_ids = kwargs.get("policy_ids")
        if policy_ids is None:
            raw_policies = self._get_raw("posture_policies", {})
            policy_ids = [
                policy["id"] for policy in raw_policies if policy.get("id") is not None
            ]
        if not policy_ids:
            return [], None

        max_workers = kwargs.get("max_workers", _POLICY_RISK_SUMMARY_MAX_WORKERS)
        workers = max(1, min(max_workers, len(policy_ids)))

        records: list[dict[str, Any]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(self._fetch_policy_detail, policy_id)
                for policy_id in policy_ids
            ]
            for future in concurrent.futures.as_completed(futures):
                records.append(future.result())

        return records, None

    def _fetch_policy_detail(self, policy_id: Any) -> dict[str, Any]:
        path = _POLICY_DETAIL_PATH.format(id=policy_id)
        record = self._get(self._base_url + path).json()

        # Stringified to match monitored_services.id (a "str" column) — the
        # raw API returns integers here, and the generic "json" coercion in
        # parse.py does a bare json.dumps with no element coercion, so a
        # left as-is int/str mismatch silently breaks any join against
        # monitored_services on this column.
        record["monitored_services"] = [
            str(service_id) for service_id in record.get("monitored_services") or []
        ]

        record["_total_rules_count"] = sum(
            counts.get("rules", 0)
            for counts in (record.get("rule_type_counts") or {}).values()
        )

        risk_levels = {
            level["name"]: level.get("risk_count", 0)
            for level in (record.get("risk_statistics") or {}).get("risk_levels", [])
        }
        for name in _RISK_LEVEL_NAMES:
            record[f"_risk_{name.lower()}_count"] = risk_levels.get(name, 0)
        record["_risk_score"] = (record.get("risk_statistics") or {}).get("risk_score")

        return record

    def _get_service_org_names(self) -> dict[Any, str]:
        """Lazily fetch and cache monitored_services id -> name for the
        client-side join used by open_policy_issues (see MANIFEST comment)."""
        if self._service_org_names is None:
            response = self._get(self._base_url + _MONITORED_SERVICES_PATH)
            self._service_org_names = {
                service["id"]: service.get("name")
                for service in response.json()
            }
        return self._service_org_names

    def _get(self, url: str, params: dict[str, Any] | None = None) -> Any:
        response = self._session.get(url, params=params, timeout=30)
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
                extra={
                    "source": "appomni",
                    "status_code": response.status_code,
                },
            )
        response.raise_for_status()
        return response
