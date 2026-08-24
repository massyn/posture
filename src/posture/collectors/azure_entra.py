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
from typing import Any, ClassVar

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
            "mail_nickname": ("mailNickname", "str"),
            "job_title": ("jobTitle", "str"),
            "company_name": ("companyName", "str"),
            "department": ("department", "str"),
            "employee_id": ("employeeId", "str"),
            "employee_type": ("employeeType", "str"),
            "employee_hire_date": ("employeeHireDate", "datetime"),
            "employee_org_data": ("employeeOrgData", "json"),
            "mobile_phone": ("mobilePhone", "str"),
            "fax_number": ("faxNumber", "str"),
            "business_phones": ("businessPhones", "json"),
            "office_location": ("officeLocation", "str"),
            "street_address": ("streetAddress", "str"),
            "city": ("city", "str"),
            "state": ("state", "str"),
            "country": ("country", "str"),
            "postal_code": ("postalCode", "str"),
            "usage_location": ("usageLocation", "str"),
            "preferred_language": ("preferredLanguage", "str"),
            "preferred_data_location": ("preferredDataLocation", "str"),
            "account_enabled": ("accountEnabled", "bool"),
            "user_type": ("userType", "str"),
            "creation_type": ("creationType", "str"),
            "external_user_state": ("externalUserState", "str"),
            "external_user_state_change_date_time": (
                "externalUserStateChangeDateTime",
                "datetime",
            ),
            "age_group": ("ageGroup", "str"),
            "consent_provided_for_minor": ("consentProvidedForMinor", "str"),
            "legal_age_group_classification": (
                "legalAgeGroupClassification",
                "str",
            ),
            "is_resource_account": ("isResourceAccount", "bool"),
            "is_management_restricted": ("isManagementRestricted", "bool"),
            "show_in_address_list": ("showInAddressList", "bool"),
            "created_date_time": ("createdDateTime", "datetime"),
            "last_password_change_date_time": (
                "lastPasswordChangeDateTime",
                "datetime",
            ),
            "sign_in_sessions_valid_from_date_time": (
                "signInSessionsValidFromDateTime",
                "datetime",
            ),
            "password_policies": ("passwordPolicies", "str"),
            "password_profile": ("passwordProfile", "json"),
            "identities": ("identities", "json"),
            "other_mails": ("otherMails", "json"),
            "im_addresses": ("imAddresses", "json"),
            "proxy_addresses": ("proxyAddresses", "json"),
            "authorization_info": ("authorizationInfo", "json"),
            "custom_security_attributes": ("customSecurityAttributes", "json"),
            "assigned_licenses": ("assignedLicenses", "json"),
            "assigned_plans": ("assignedPlans", "json"),
            "license_assignment_states": ("licenseAssignmentStates", "json"),
            "on_premises_sync_enabled": ("onPremisesSyncEnabled", "bool"),
            "on_premises_last_sync_date_time": (
                "onPremisesLastSyncDateTime",
                "datetime",
            ),
            "on_premises_immutable_id": ("onPremisesImmutableId", "str"),
            "on_premises_distinguished_name": (
                "onPremisesDistinguishedName",
                "str",
            ),
            "on_premises_domain_name": ("onPremisesDomainName", "str"),
            "on_premises_sam_account_name": ("onPremisesSamAccountName", "str"),
            "on_premises_security_identifier": (
                "onPremisesSecurityIdentifier",
                "str",
            ),
            "on_premises_user_principal_name": (
                "onPremisesUserPrincipalName",
                "str",
            ),
            "on_premises_extension_attributes": (
                "onPremisesExtensionAttributes",
                "json",
            ),
            "on_premises_provisioning_errors": (
                "onPremisesProvisioningErrors",
                "json",
            ),
            "security_identifier": ("securityIdentifier", "str"),
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
    display_name = "EntraID"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {
        "tenant_id": True,
        "client_id": True,
        "client_secret": True,
    }

    def _authenticate(self) -> None:
        token = fetch_azure_ad_token(
            self._session,
            tenant_id=self._config["tenant_id"],
            client_id=self._config["client_id"],
            client_secret=self._config["client_secret"],
            scope="https://graph.microsoft.com/.default",
            source="Azure Entra",
        )
        self._session.headers["Authorization"] = f"Bearer {token.access_token}"
        self._token_expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=token.expires_in
        )

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
            if resource == "users" and not select_fields:
                # accountEnabled, createdDateTime, department, userType and
                # lastPasswordChangeDateTime aren't in Graph's default /users
                # field set — without an explicit $select they come back
                # missing, not null. Request every manifest column's source
                # field so they're populated.
                select_fields = sorted(
                    {source for source, _ in MANIFEST["users"]["columns"].values()}
                )
            if select_fields:
                params["$select"] = ",".join(select_fields)

        records, next_link = odata_get_page(self._session, url, params)
        return records, next_link
