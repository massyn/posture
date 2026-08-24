"""Google Workspace collector, via the Admin SDK Directory API.

Raw ``requests`` against ``https://admin.googleapis.com`` — no vendor SDK
for the data calls (only the auth step needs a dependency; see
``_google_oauth.py``'s docstring for why). Auth is a service-account
JWT-bearer flow with domain-wide delegation, impersonating a real super
admin via the ``admin_email`` config.

One token, requested once per collector instance, covers every resource:
``_authenticate`` asks for the union of every resource's required scope
(``_SCOPES`` below) in a single JWT, the same "one auth covers everything"
shape Intune/MDE/Teams get for free from Graph's ``.default`` scope.
Unlike those, Google's scopes are explicit at token-request time, not
implicit from prior admin consent — so if the domain admin's domain-wide
delegation authorization (Admin console > Security > API controls) is
missing even one of ``_SCOPES``, the entire token request is rejected as
``AuthenticationError`` and *no* resource collects, not just the one
needing the missing scope. This is the opposite failure shape to Slack's
per-resource ``missing_scope`` degradation — document it for operators
rather than trying to work around it (there's no way to discover which
scopes are pre-authorized without attempting the exchange).

``customer`` defaults to Google's ``my_customer`` alias (the caller's own
domain) — no separate customer-id lookup call needed; override via the
optional ``customer_id`` config for reseller/multi-customer setups.

``group_members``, like Okta's ``group_members``/``user_factors``, is not
``derived_from`` "groups": each group's members are their own paginated
network call, fanned out across a thread pool, with ``_group_id`` injected
client-side. ``requires="groups"`` so the group id list is served from the
on-disk cache instead of re-collecting the full resource a second time.

Resources: ``users``, ``groups``, ``group_members`` (requires groups ids),
``roles``, ``role_assignments``, ``org_units``.

**Caveat:** field names were verified against Google's current REST
reference (not a live tenant) — same caveat as ``cloudflare.py``. Worth a
quick check against a real tenant response before relying on this
collector.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar

from posture.base import Collector
from posture.collectors._google_oauth import (
    fetch_google_workspace_token,
    google_get_json,
)

_BASE_URL = "https://admin.googleapis.com"
_PAGE_SIZE = 200
_DEFAULT_CUSTOMER = "my_customer"

# Union of every resource's required scope — see module docstring for why
# this is requested as one token rather than per-resource.
_SCOPES = [
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.member.readonly",
    "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
    "https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
]

_MAX_FANOUT_WORKERS = 5

_USERS_PATH = "/admin/directory/v1/users"
_GROUPS_PATH = "/admin/directory/v1/groups"
_GROUP_MEMBERS_PATH = "/admin/directory/v1/groups/{group_key}/members"
_ROLES_PATH = "/admin/directory/v1/customer/{customer}/roles"
_ROLE_ASSIGNMENTS_PATH = "/admin/directory/v1/customer/{customer}/roleassignments"
_ORG_UNITS_PATH = "/admin/directory/v1/customer/{customer}/orgunits"

MANIFEST: dict[str, dict[str, Any]] = {
    "users": {
        "endpoint": _USERS_PATH,
        "columns": {
            "user_id": ("id", "str"),
            "primary_email": ("primaryEmail", "str"),
            "full_name": ("name.fullName", "str"),
            "given_name": ("name.givenName", "str"),
            "family_name": ("name.familyName", "str"),
            "is_admin": ("isAdmin", "bool"),
            "is_delegated_admin": ("isDelegatedAdmin", "bool"),
            "suspended": ("suspended", "bool"),
            "suspension_reason": ("suspensionReason", "str"),
            "archived": ("archived", "bool"),
            "org_unit_path": ("orgUnitPath", "str"),
            "is_enforced_in_2sv": ("isEnforcedIn2Sv", "bool"),
            "is_enrolled_in_2sv": ("isEnrolledIn2Sv", "bool"),
            "last_login_time": ("lastLoginTime", "datetime"),
            "creation_time": ("creationTime", "datetime"),
            "change_password_at_next_login": ("changePasswordAtNextLogin", "bool"),
            "ip_whitelisted": ("ipWhitelisted", "bool"),
            "agreed_to_terms": ("agreedToTerms", "bool"),
            "recovery_email": ("recoveryEmail", "str"),
            "recovery_phone": ("recoveryPhone", "str"),
            "include_in_global_address_list": (
                "includeInGlobalAddressList",
                "bool",
            ),
        },
    },
    "groups": {
        "endpoint": _GROUPS_PATH,
        "columns": {
            "group_id": ("id", "str"),
            "email": ("email", "str"),
            "name": ("name", "str"),
            "description": ("description", "str"),
            "admin_created": ("adminCreated", "bool"),
            "direct_members_count": ("directMembersCount", "int"),
            "aliases": ("aliases", "json"),
        },
    },
    "group_members": {
        # Not derived_from "groups": each group's members are their own
        # paginated network call, fanned out across a thread pool.
        # _group_id is injected client-side (see _fetch_all_for_group).
        "requires": "groups",
        "endpoint": _GROUP_MEMBERS_PATH,
        "columns": {
            "group_id": ("_group_id", "str"),
            "member_id": ("id", "str"),
            "email": ("email", "str"),
            "role": ("role", "str"),
            "type": ("type", "str"),
            "status": ("status", "str"),
        },
    },
    "roles": {
        "endpoint": _ROLES_PATH,
        "columns": {
            "role_id": ("roleId", "str"),
            "role_name": ("roleName", "str"),
            "role_description": ("roleDescription", "str"),
            "is_super_admin_role": ("isSuperAdminRole", "bool"),
            "is_system_role": ("isSystemRole", "bool"),
            "role_privileges": ("rolePrivileges", "json"),
        },
    },
    "role_assignments": {
        "endpoint": _ROLE_ASSIGNMENTS_PATH,
        "columns": {
            "role_assignment_id": ("roleAssignmentId", "str"),
            "role_id": ("roleId", "str"),
            "assigned_to": ("assignedTo", "str"),
            "assignee_type": ("assigneeType", "str"),
            "scope_type": ("scopeType", "str"),
            "org_unit_id": ("orgUnitId", "str"),
        },
    },
    "org_units": {
        "endpoint": _ORG_UNITS_PATH,
        "columns": {
            "org_unit_id": ("orgUnitId", "str"),
            "org_unit_path": ("orgUnitPath", "str"),
            "name": ("name", "str"),
            "description": ("description", "str"),
            "parent_org_unit_id": ("parentOrgUnitId", "str"),
            "parent_org_unit_path": ("parentOrgUnitPath", "str"),
            "block_inheritance": ("blockInheritance", "bool"),
        },
    },
}

# resource -> (response's list field name, whether it needs $customer)
_LIST_RESOURCES: dict[str, tuple[str, bool]] = {
    "users": ("users", True),
    "groups": ("groups", True),
    "roles": ("items", False),
    "role_assignments": ("items", False),
    "org_units": ("organizationUnits", False),
}


class GoogleWorkspaceCollector(Collector):
    env_prefix = "GOOGLE_WORKSPACE"
    display_name = "Google Workspace"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {
        "service_account_json_path": True,
        "admin_email": True,
        "customer_id": False,
    }

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        self._customer = self._config.get("customer_id") or _DEFAULT_CUSTOMER

    def _authenticate(self) -> None:
        token = fetch_google_workspace_token(
            self._session,
            service_account_json_path=self._config["service_account_json_path"],
            admin_email=self._config["admin_email"],
            scopes=_SCOPES,
            source="Google Workspace",
        )
        self._session.headers["Authorization"] = f"Bearer {token.access_token}"
        self._token_expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=token.expires_in
        )

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource in _LIST_RESOURCES:
            return self._fetch_list_page(resource, kwargs, cursor)
        if resource == "group_members":
            return self._fetch_group_members_page(kwargs, cursor)
        raise ValueError(f"Unsupported resource '{resource}'")

    def _fetch_list_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        list_key, needs_customer = _LIST_RESOURCES[resource]
        path = self.manifest[resource]["endpoint"]
        if "{customer}" in path:
            path = path.format(customer=self._customer)
        params: dict[str, Any] = {"maxResults": _PAGE_SIZE}
        if needs_customer:
            params["customer"] = self._customer
        if cursor:
            params["pageToken"] = cursor
        params.update(kwargs)

        body = google_get_json(self._session, _BASE_URL + path, params)
        records = body.get(list_key) or []
        return records, body.get("nextPageToken") or None

    def _fetch_group_members_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # entire fan-out already completed on first call

        group_ids = kwargs.get("group_ids")
        if group_ids is None:
            raw_groups = self._get_raw("groups", {})
            group_ids = [g["id"] for g in raw_groups if g.get("id")]
        if not group_ids:
            return [], None

        max_workers = kwargs.get("max_workers", _MAX_FANOUT_WORKERS)
        workers = max(1, min(max_workers, len(group_ids)))

        all_records = self._resumable_fanout(
            "group_members", group_ids, self._fetch_all_for_group, workers
        )
        return all_records, None

    def _fetch_all_for_group(self, group_id: str) -> list[dict[str, Any]]:
        path = _GROUP_MEMBERS_PATH.format(group_key=group_id)
        records: list[dict[str, Any]] = []
        cursor: str | None = None
        while True:
            params: dict[str, Any] = {"maxResults": _PAGE_SIZE}
            if cursor:
                params["pageToken"] = cursor
            body = google_get_json(self._session, _BASE_URL + path, params)
            page_records = body.get("members") or []
            for record in page_records:
                record["_group_id"] = group_id
            records.extend(page_records)
            cursor = body.get("nextPageToken") or None
            if not cursor:
                break
        return records
