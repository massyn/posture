"""Qualys Policy Compliance (Secure Configuration) tables, read through the
same ``/fo/`` XML API as VMDR (see ``fo_api.py``).

The PCRS posture-streaming JSON API (``/pcrs/.../postureInfo``) was not used:
it needs the gateway host and JWT auth flow, and Qualys's own docs contradict
each other on whether its supported versions still cover SCA.

- ``compliance_policies``: ``/api/4.0/fo/compliance/policy/`` (the v2/v3
  paths are EOL December 2026). At most 1,000 policies per response, with a
  ``WARNING/URL`` follow-up beyond that; ``truncation_limit`` isn't a
  documented parameter here, so it isn't sent.
- ``compliance_policy_controls``: derived from ``compliance_policies``'
  ``CONTROL_LIST``, one row per policy and control, carrying the control
  statement and criticality the posture rows don't.
- ``compliance_posture``: ``/api/2.0/fo/compliance/posture/info/``, one row
  per posture (host, control and technology instance). The endpoint requires
  a policy, and truncation (``WARNING/URL``) only works with a single
  ``policy_id``, so it is queried one policy at a time: the cursor is
  ``(policy index, follow-up URL)``. Policies come from
  ``compliance_policies`` (``requires``, so its records are cached and
  reused) unless the ``policy_ids`` kwarg names them. Posture records carry
  no policy id of their own, so it is injected at fetch time; Qualys's
  ``N/A`` placeholder for never-failed/never-passed dates is mapped to null
  at the same point.

kwargs: ``compliance_policies`` and ``compliance_posture`` pass any kwargs
through as Qualys query parameters (e.g. ``status="Failed"``,
``criticality_values="4,5"``). ``compliance_posture`` additionally takes
``policy_ids``, a list of policy ids to restrict the run to.

Exception details are not collected: Qualys's docs give no element names for
them.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from posture.collectors.qualys.fo_api import FoApi

_POLICY_LIST_PATH = "/api/4.0/fo/compliance/policy/"
_POSTURE_INFO_PATH = "/api/2.0/fo/compliance/posture/info/"

# Qualys renders "never happened" posture dates as the literal "N/A".
_NOT_APPLICABLE = "N/A"

MANIFEST: dict[str, dict[str, Any]] = {
    "compliance_policies": {
        "columns": {
            "policy_id": ("ID", "str"),
            "title": ("TITLE", "str"),
            "status": ("STATUS", "str"),
            "is_locked": ("IS_LOCKED", "bool"),
            "evaluate_now": ("EVALUATE_NOW", "str"),
            "asset_group_ids": ("ASSET_GROUP_IDS", "str"),
            "created": ("CREATED.DATETIME", "datetime"),
            "created_by": ("CREATED.BY", "str"),
            "last_modified": ("LAST_MODIFIED.DATETIME", "datetime"),
            "last_modified_by": ("LAST_MODIFIED.BY", "str"),
            "last_evaluated": ("LAST_EVALUATED.DATETIME", "datetime"),
        },
    },
    "compliance_policy_controls": {
        "derived_from": "compliance_policies",
        "record_path": "CONTROL_LIST.CONTROL",
        "columns": {
            "policy_id": ("$parent.ID", "str"),
            "policy_title": ("$parent.TITLE", "str"),
            "control_id": ("ID", "str"),
            "statement": ("STATEMENT", "str"),
            "criticality_label": ("CRITICALITY.LABEL", "str"),
            "criticality_value": ("CRITICALITY.VALUE", "int"),
            "status": ("STATUS", "str"),
        },
    },
    "compliance_posture": {
        "requires": "compliance_policies",
        "columns": {
            "posture_id": ("ID", "str"),
            "policy_id": ("POLICY_ID", "str"),
            "host_id": ("HOST_ID", "str"),
            "control_id": ("CONTROL_ID", "str"),
            "technology_id": ("TECHNOLOGY_ID", "str"),
            "instance": ("INSTANCE", "str"),
            "status": ("STATUS", "str"),
            "previous_status": ("PREVIOUS_STATUS", "str"),
            "posture_modified": ("POSTURE_MODIFIED_DATE", "datetime"),
            "last_evaluated": ("EVALUATION_DATE", "datetime"),
            "first_failed": ("FIRST_FAIL_DATE", "datetime"),
            "last_failed": ("LAST_FAIL_DATE", "datetime"),
            "first_passed": ("FIRST_PASS_DATE", "datetime"),
            "last_passed": ("LAST_PASS_DATE", "datetime"),
        },
    },
}


class ComplianceApi:
    resources = ("compliance_policies", "compliance_posture")

    def __init__(
        self,
        fo: FoApi,
        get_raw: Callable[[str, dict[str, Any]], list[dict[str, Any]]],
    ) -> None:
        self._fo = fo
        # The collector's cached raw-records reader, so compliance_posture
        # reuses compliance_policies' records rather than re-fetching them.
        self._get_raw = get_raw

    def fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "compliance_policies":
            return self._fo.fetch_list_page(
                cursor,
                path=_POLICY_LIST_PATH,
                params={"action": "list", "details": "Basic", **kwargs},
                list_path=("RESPONSE", "POLICY_LIST", "POLICY"),
                paginated=False,
            )

        params = dict(kwargs)
        policy_ids = params.pop("policy_ids", None)
        if policy_ids is None:
            policy_ids = [
                policy["ID"] for policy in self._get_raw("compliance_policies", {})
            ]
        if not policy_ids:
            return [], None

        index, follow_up_url = cursor if cursor is not None else (0, None)
        policy_id = str(policy_ids[index])
        records, next_url = self._fo.fetch_list_page(
            follow_up_url,
            path=_POSTURE_INFO_PATH,
            params={"action": "list", "policy_id": policy_id, **params},
            list_path=("RESPONSE", "INFO_LIST", "INFO"),
        )
        records = [
            {
                **{k: None if v == _NOT_APPLICABLE else v for k, v in record.items()},
                "POLICY_ID": policy_id,
            }
            for record in records
        ]

        if next_url is not None:
            return records, (index, next_url)
        if index + 1 < len(policy_ids):
            return records, (index + 1, None)
        return records, None
