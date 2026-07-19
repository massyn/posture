"""Microsoft Entra ID (Azure AD) collector.

Raw ``requests`` against Microsoft Graph — no vendor SDK. Auth is Azure AD
client-credentials, shared with ``intune.py`` and ``mde.py`` via
``_azure_oauth.py``; pagination is Graph's standard ``value`` /
``@odata.nextLink`` envelope, same as Intune.

No incremental sync: ``signins`` accepts a ``days`` kwarg (default 180) that
narrows the server-side ``$filter``, but every collect() is still a full
snapshot as of the call — it does not track a checkpoint across runs, per
posture's locked "full pull, point in time, no incremental sync, ever"
decision.

Resources: ``users``, ``signins``, ``audit_logs``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from posture.base import Collector
from posture.collectors._azure_oauth import fetch_azure_ad_token, odata_get_page

_GRAPH_BASE_URL = "https://graph.microsoft.com"
_PAGE_SIZE = 100
_DEFAULT_SIGNIN_DAYS = 180

_ENDPOINTS = {
    "users": "/v1.0/users",
    "signins": "/v1.0/auditLogs/signIns",
    "audit_logs": "/v1.0/auditLogs/directoryAudits",
}

MANIFEST: dict[str, dict[str, Any]] = {
    "users": {
        "endpoint": _ENDPOINTS["users"],
        "columns": {
            "user_id": ("id", "str"),
            "display_name": ("displayName", "str"),
            "given_name": ("givenName", "str"),
            "surname": ("surname", "str"),
            "user_principal_name": ("userPrincipalName", "str"),
            "mail": ("mail", "str"),
            "job_title": ("jobTitle", "str"),
            "department": ("department", "str"),
            "mobile_phone": ("mobilePhone", "str"),
            "business_phones": ("businessPhones", "json"),
            "office_location": ("officeLocation", "str"),
            "preferred_language": ("preferredLanguage", "str"),
            "account_enabled": ("accountEnabled", "bool"),
            "user_type": ("userType", "str"),
            "created_date_time": ("createdDateTime", "datetime"),
            "last_password_change_date_time": (
                "lastPasswordChangeDateTime",
                "datetime",
            ),
        },
    },
    "signins": {
        "endpoint": _ENDPOINTS["signins"],
        "columns": {
            "user_principal_name": ("userPrincipalName", "str"),
            "created_date_time": ("createdDateTime", "datetime"),
        },
    },
    "audit_logs": {
        "endpoint": _ENDPOINTS["audit_logs"],
        "columns": {
            "audit_log_id": ("id", "str"),
            "activity_display_name": ("activityDisplayName", "str"),
            "activity_date_time": ("activityDateTime", "datetime"),
            "user_principal_name": (
                "targetResources.0.userPrincipalName",
                "str",
            ),
            "initiated_by_user": ("initiatedBy.user.userPrincipalName", "str"),
            "initiated_by_app": ("initiatedBy.app.displayName", "str"),
        },
    },
}


class AzureEntraCollector(Collector):
    env_prefix = "AZURE"
    manifest = MANIFEST
    required_config_keys = ("tenant_id", "client_id", "client_secret")

    def _authenticate(self) -> None:
        token = fetch_azure_ad_token(
            self._session,
            tenant_id=self._config["tenant_id"],
            client_id=self._config["client_id"],
            client_secret=self._config["client_secret"],
            scope="https://graph.microsoft.com/.default",
            source="Azure Entra",
        )
        self._session.headers["Authorization"] = f"Bearer {token}"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            records, next_link = odata_get_page(self._session, cursor, None)
            return records, next_link

        url = _GRAPH_BASE_URL + _ENDPOINTS[resource]
        params: dict[str, Any] = {"$top": _PAGE_SIZE}
        if resource == "signins":
            days = kwargs.get("days", _DEFAULT_SIGNIN_DAYS)
            cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            params["$filter"] = f"createdDateTime ge {cutoff}"
        else:
            select_fields = kwargs.get("select")
            if select_fields:
                params["$select"] = ",".join(select_fields)

        records, next_link = odata_get_page(self._session, url, params)
        return records, next_link
