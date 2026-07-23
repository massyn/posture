"""Microsoft Intune collector.

Raw ``requests`` against Microsoft Graph — no vendor SDK. Auth is Azure AD
client-credentials (shared with ``mde.py`` via ``_azure_oauth.py``);
pagination is Graph's standard ``value`` / ``@odata.nextLink`` envelope.

Schema note: unlike most posture collectors, the reference implementation's
``device_configurations`` normaliser keeps *every* top-level field via
generic flattening plus a handful of named aliases. posture's manifest is
allowlist-only, so only the named aliases are ported — narrower than what
the accelerator captures in production, not a guess at the rest.

No incremental sync: the reference supports `$filter`-based checkpointing,
which conflicts with posture's locked "full pull, point in time, no
incremental sync, ever" decision. Every collect() here is a full snapshot.

Resources: ``managed_devices``, ``users``, ``device_configurations``,
``managed_device_detail`` (requires managed_devices ids),
``device_configuration_detail`` (requires device_configurations ids),
``device_compliance_policies``, ``attack_simulations``,
``attack_simulation_users`` (requires attack_simulations ids).
"""

from __future__ import annotations

import concurrent.futures
import logging
from typing import Any

import requests

from posture.base import Collector
from posture.collectors._azure_oauth import (
    fetch_azure_ad_token,
    graph_get_json,
    odata_get_page,
)

logger = logging.getLogger("posture.collectors.intune")

_GRAPH_BASE_URL = "https://graph.microsoft.com"
_PAGE_SIZE = 100

# Per-item fan-out (managed_device_detail, device_configuration_detail,
# attack_simulation_users) issues one request per id/simulation. Bounded
# thread pool overlaps network latency instead of paying it serially — see
# CLAUDE.md "Performance: per-item fan-out" for the pattern and its limits.
_MAX_FANOUT_WORKERS = 10

_ENDPOINTS = {
    "managed_devices": "/v1.0/deviceManagement/managedDevices",
    "users": "/v1.0/users",
    "device_configurations": "/v1.0/deviceManagement/deviceConfigurations",
    "managed_device_detail": "/beta/deviceManagement/managedDevices/{id}",
    "device_configuration_detail": "/v1.0/deviceManagement/deviceConfigurations/{id}",
    "device_compliance_policies": "/v1.0/deviceManagement/deviceCompliancePolicies",
    "attack_simulations": "/v1.0/security/attackSimulation/simulations",
    "attack_simulation_users": "/v1.0/security/attackSimulation/simulations/{id}/report/simulationUsers",
}

_DEVICE_COLUMNS = {
    "device_id": ("id", "str"),
    "device_name": ("deviceName", "str"),
    "operating_system": ("operatingSystem", "str"),
    "os_version": ("osVersion", "str"),
    "os_build_number": ("osBuildNumber", "str"),
}

# managed_device_detail hits the beta managedDevices/{id} endpoint, which
# carries several top-level fields the v1.0 list endpoint doesn't — cf02
# needs all of them, so they're only added here rather than to the shared
# _DEVICE_COLUMNS used by the v1.0 managed_devices list.
_DEVICE_DETAIL_COLUMNS = {
    **_DEVICE_COLUMNS,
    "is_encrypted": ("isEncrypted", "bool"),
    "compliance_state": ("complianceState", "str"),
    "device_guard_vbs_state": ("deviceGuardVirtualizationBasedSecurityState", "str"),
    "device_guard_credential_guard_state": (
        "deviceGuardLocalSystemAuthorityCredentialGuardState",
        "str",
    ),
    "windows_active_malware_count": ("windowsActiveMalwareCount", "int"),
    "last_sync_datetime": ("lastSyncDateTime", "datetime"),
    "user_principal_name": ("userPrincipalName", "str"),
}

_CONFIGURATION_COLUMNS = {
    "configuration_id": ("id", "str"),
    "display_name": ("displayName", "str"),
    "description": ("description", "str"),
    "created_date_time": ("createdDateTime", "datetime"),
    "last_modified_date_time": ("lastModifiedDateTime", "datetime"),
    "platforms": ("platforms", "str"),
    "technologies": ("technologies", "str"),
    "role_scope_tag_ids": ("roleScopeTagIds", "json"),
    "settings_json": ("settings", "json"),
    "assignments_json": ("assignments", "json"),
}

MANIFEST: dict[str, dict[str, Any]] = {
    "managed_devices": {
        "endpoint": _ENDPOINTS["managed_devices"],
        "columns": _DEVICE_COLUMNS,
    },
    "users": {
        "endpoint": _ENDPOINTS["users"],
        "columns": {
            "user_id": ("id", "str"),
            "display_name": ("displayName", "str"),
            "given_name": ("givenName", "str"),
            "surname": ("surname", "str"),
            "user_principal_name": ("userPrincipalName", "str"),
            "mail": ("mail", "str"),
            "business_phones": ("businessPhones", "json"),
            "mobile_phone": ("mobilePhone", "str"),
            "office_location": ("officeLocation", "str"),
            "preferred_language": ("preferredLanguage", "str"),
            "job_title": ("jobTitle", "str"),
        },
    },
    "device_configurations": {
        "endpoint": _ENDPOINTS["device_configurations"],
        "columns": _CONFIGURATION_COLUMNS,
    },
    "managed_device_detail": {
        # Not derived_from "managed_devices": each device's detail is its own
        # network call by id, not data nested inside the list record.
        "endpoint": _ENDPOINTS["managed_device_detail"],
        "columns": _DEVICE_DETAIL_COLUMNS,
    },
    "device_configuration_detail": {
        "endpoint": _ENDPOINTS["device_configuration_detail"],
        "columns": _CONFIGURATION_COLUMNS,
    },
    "device_compliance_policies": {
        "endpoint": _ENDPOINTS["device_compliance_policies"],
        "columns": {
            "policy_id": ("id", "str"),
            "display_name": ("displayName", "str"),
            "created_date_time": ("createdDateTime", "datetime"),
            "last_modified_date_time": ("lastModifiedDateTime", "datetime"),
        },
    },
    "attack_simulations": {
        "endpoint": _ENDPOINTS["attack_simulations"],
        "columns": {
            # @odata.etag is deliberately omitted: a literal dotted key our
            # path-plucker can't address without a DSL escape hatch, and not
            # essential data (a caching/concurrency token).
            "simulation_id": ("id", "str"),
            "display_name": ("displayName", "str"),
            "description": ("description", "str"),
            "attack_type": ("attackType", "str"),
            "payload_delivery_platform": ("payloadDeliveryPlatform", "str"),
            "attack_technique": ("attackTechnique", "str"),
            "status": ("status", "str"),
            "created_date_time": ("createdDateTime", "datetime"),
            "last_modified_date_time": ("lastModifiedDateTime", "datetime"),
            "launch_date_time": ("launchDateTime", "datetime"),
            "completion_date_time": ("completionDateTime", "datetime"),
            "is_automated": ("isAutomated", "bool"),
            "automation_id": ("automationId", "str"),
            "duration_in_days": ("durationInDays", "int"),
            "training_setting_json": ("trainingSetting", "json"),
            "oauth_consent_app_detail_json": ("oAuthConsentAppDetail", "json"),
            "end_user_notification_setting_json": (
                "endUserNotificationSetting",
                "json",
            ),
            "included_account_target_json": ("includedAccountTarget", "json"),
            "excluded_account_target_json": ("excludedAccountTarget", "json"),
            "created_by_email": ("createdBy.email", "str"),
            "created_by_id": ("createdBy.id", "str"),
            "created_by_display_name": ("createdBy.displayName", "str"),
            "last_modified_by_email": ("lastModifiedBy.email", "str"),
            "last_modified_by_id": ("lastModifiedBy.id", "str"),
            "last_modified_by_display_name": ("lastModifiedBy.displayName", "str"),
        },
    },
    "attack_simulation_users": {
        # Not derived_from "attack_simulations": each simulation's user
        # report is its own paginated network call, not data nested inside
        # the simulation record. _simulation_id is injected client-side
        # (see _fetch_attack_simulation_users_page) since the simulationUsers
        # response body doesn't carry it — it's implied by the request URL.
        # simulationEvents/trainingEvents are per-user lists of nested
        # objects (click/report timestamps, training progress) — kept as
        # json blobs rather than exploded into further derived resources,
        # consistent with how device_configurations treats nested lists.
        "endpoint": _ENDPOINTS["attack_simulation_users"],
        "columns": {
            "simulation_id": ("_simulation_id", "str"),
            "user_id": ("simulationUser.userId", "str"),
            "display_name": ("simulationUser.displayName", "str"),
            "email": ("simulationUser.email", "str"),
            "is_compromised": ("isCompromised", "bool"),
            "compromised_date_time": ("compromisedDateTime", "datetime"),
            "assigned_trainings_count": ("assignedTrainingsCount", "int"),
            "completed_trainings_count": ("completedTrainingsCount", "int"),
            "in_progress_trainings_count": ("inProgressTrainingsCount", "int"),
            "reported_phish_date_time": ("reportedPhishDateTime", "datetime"),
            "simulation_events_json": ("simulationEvents", "json"),
            "training_events_json": ("trainingEvents", "json"),
        },
    },
}

_DETAIL_RESOURCE_SOURCES = {
    "managed_device_detail": "managed_devices",
    "device_configuration_detail": "device_configurations",
}


class IntuneCollector(Collector):
    env_prefix = "INTUNE"
    manifest = MANIFEST
    required_config_keys = ("tenant_id", "client_id", "client_secret")

    def _authenticate(self) -> None:
        token = fetch_azure_ad_token(
            self._session,
            tenant_id=self._config["tenant_id"],
            client_id=self._config["client_id"],
            client_secret=self._config["client_secret"],
            scope="https://graph.microsoft.com/.default",
            source="Intune",
        )
        self._session.headers["Authorization"] = f"Bearer {token}"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "attack_simulation_users":
            return self._fetch_attack_simulation_users_page(kwargs, cursor)
        if resource in _DETAIL_RESOURCE_SOURCES:
            return self._fetch_detail_page(resource, kwargs, cursor)
        return self._fetch_list_page(resource, kwargs, cursor)

    def _fetch_list_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            records, next_link = odata_get_page(self._session, cursor, None)
        else:
            url = _GRAPH_BASE_URL + _ENDPOINTS[resource]
            params: dict[str, Any] = {"$top": _PAGE_SIZE}
            select_fields = kwargs.get("select")
            if select_fields:
                params["$select"] = ",".join(select_fields)
            records, next_link = odata_get_page(self._session, url, params)

        return records, next_link

    def _fetch_detail_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # all ids already fetched on the first call

        ids = kwargs.get("ids")
        if ids is None:
            source_resource = _DETAIL_RESOURCE_SOURCES[resource]
            raw_source = self._get_raw(source_resource, {})
            ids = [str(r["id"]) for r in raw_source if r.get("id") is not None]
        if not ids:
            return [], None

        path_template = _ENDPOINTS[resource]

        def _fetch_one(record_id: str) -> dict[str, Any] | None:
            url = _GRAPH_BASE_URL + path_template.format(id=record_id)
            try:
                return graph_get_json(self._session, url, None)
            except requests.exceptions.HTTPError as exc:
                status = exc.response.status_code if exc.response is not None else None
                if status == 404:
                    # Per-item detail endpoint: a 404 means this item no
                    # longer exists (e.g. device deregistered since the list
                    # was pulled), not a collection-wide failure.
                    logger.info(
                        "%s: no detail for id (404), skipping",
                        resource,
                        extra={
                            "source": self.env_prefix.lower(),
                            "resource": resource,
                            "record_id": record_id,
                        },
                    )
                    return None
                raise

        records: list[dict[str, Any]] = []
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=_MAX_FANOUT_WORKERS
        ) as executor:
            futures = {
                executor.submit(_fetch_one, record_id): record_id for record_id in ids
            }
            try:
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result is not None:
                        records.append(result)
            except BaseException:
                # A worker failed (e.g. token expired mid-run, raising
                # UnauthorizedSignal via graph_get_json). Cancel every future
                # that hasn't started yet so the pool doesn't keep burning
                # through the remaining queue against a dead token before
                # __exit__'s shutdown(wait=True) can return control to
                # base.py's retry/reauth handler.
                for pending in futures:
                    pending.cancel()
                raise

        return records, None

    def _fetch_attack_simulation_users_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # entire fan-out already completed on first call

        simulation_ids = kwargs.get("simulation_ids")
        if simulation_ids is None:
            raw_simulations = self._get_raw("attack_simulations", {})
            simulation_ids = [
                str(s["id"]) for s in raw_simulations if s.get("id") is not None
            ]
        if not simulation_ids:
            return [], None

        path_template = _ENDPOINTS["attack_simulation_users"]

        def _fetch_one(simulation_id: str) -> list[dict[str, Any]]:
            try:
                sim_records = self._drain_simulation_users(
                    path_template.format(id=simulation_id)
                )
            except requests.exceptions.HTTPError as exc:
                status = exc.response.status_code if exc.response is not None else None
                if status == 404:
                    # A simulation deleted since attack_simulations was
                    # pulled 404s here — per-simulation, not a
                    # collection-wide failure. Skip it rather than letting
                    # the exception propagate and force base.py to discard
                    # every other simulation's already-fetched users.
                    logger.info(
                        "attack_simulation_users: no data for simulation "
                        "(404), skipping",
                        extra={
                            "source": self.env_prefix.lower(),
                            "simulation_id": simulation_id,
                        },
                    )
                    return []
                raise
            for record in sim_records:
                record["_simulation_id"] = simulation_id
            return sim_records

        records: list[dict[str, Any]] = []
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=_MAX_FANOUT_WORKERS
        ) as executor:
            futures = {
                executor.submit(_fetch_one, simulation_id): simulation_id
                for simulation_id in simulation_ids
            }
            try:
                for future in concurrent.futures.as_completed(futures):
                    records.extend(future.result())
            except BaseException:
                # See _fetch_detail_page: cancel unstarted futures on first
                # failure so a dead token doesn't get retried against the
                # whole remaining queue before base.py can reauth.
                for pending in futures:
                    pending.cancel()
                raise

        return records, None

    def _drain_simulation_users(self, path: str) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        url = _GRAPH_BASE_URL + path
        params: dict[str, Any] | None = {"$top": _PAGE_SIZE}
        while url:
            page_records, next_link = odata_get_page(self._session, url, params)
            records.extend(page_records)
            url = next_link
            params = None  # nextLink already encodes query state
        return records
