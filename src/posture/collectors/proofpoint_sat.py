"""Proofpoint Security Awareness Training (PSAT / ZenGuide) collector.

Raw ``requests`` against the PSAT Results (reporting) API v0.3.0 — no vendor
SDK. Auth is a static API key sent as the ``x-apikey-token`` header, the same
"just set the header" shape as AppOmni/Snyk/UpGuard. The API host is
region-specific (``results.us.securityeducation.com`` and friends) with no
cross-tenant discovery, so ``region`` picks it, defaulting to ``us`` like
``knowbe4.py``.

Every resource is its own top-level report endpoint returning a JSON:API
envelope (``{"data": [{"id", "type", "attributes": {...}}], "meta":
{"count", "page_number", "page_size"}, "links": {"next", ...}}``) — no
fan-out, no ``derived_from``. Pagination is ``page[number]``/``page[size]``:
keep requesting the next page while ``links.next`` is present or
``meta.count`` says more rows remain, the same stop rule as Proofpoint's own
community client (``psat-api``).

``user_tag_enable=TRUE`` is sent by default so each row carries the tenant's
custom user tags (``usertags``); PSAT omits them otherwise. kwargs are passed
straight through as query parameters in PSAT's own filter dialect (e.g.
``**{"filter[_eventtimestamp_start]": "2026-01-01"}``) and win over that
default.

``phishing_extended`` (per-click event detail) is deliberately not collected:
it is disabled by default in PSAT tenants and has to be enabled by
Proofpoint.

Resources: ``users``, ``training``, ``phishing``, ``cyberstrength``,
``phishalarm``.

**Caveat:** ``MANIFEST`` column paths below were built from Proofpoint's
community ``psat-api`` client (pfptcommunity) and public integration docs,
not a live schema introspection against a real tenant — same caveat as
``wiz.py``, ``appomni.py``, ``phriendly_phishing.py``, and others. Verify
field names, date formats and the pagination envelope against a real
tenant's response before relying on this collector.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger = logging.getLogger("posture.collectors.proofpoint_sat")

_REGION_HOSTS = {
    "us": "results.us.securityeducation.com",
    "eu": "results.eu.securityeducation.com",
    "ap": "results.ap.securityeducation.com",
    "ca": "results.zenguide.ca",
    "in": "results.securityeducation.in",
}
_DEFAULT_REGION = "us"
_API_ROOT = "/api/reporting/v0.3.0"
_PAGE_SIZE = 5000

# Identity columns PSAT includes on every report row.
_USER_COLUMNS: dict[str, tuple[str, str]] = {
    "id": ("id", "str"),
    "user_first_name": ("attributes.userfirstname", "str"),
    "user_last_name": ("attributes.userlastname", "str"),
    "user_email_address": ("attributes.useremailaddress", "str"),
    "user_active": ("attributes.useractiveflag", "bool"),
    "user_deleted_date": ("attributes.userdeleteddate", "datetime"),
    "sso_id": ("attributes.sso_id", "str"),
    "user_tags": ("attributes.usertags", "json"),
}

MANIFEST: dict[str, dict[str, Any]] = {
    "users": {
        "endpoint": "/users",
        "columns": {
            **_USER_COLUMNS,
            "locale": ("attributes.userlocale", "str"),
            "timezone": ("attributes.usertimezone", "str"),
            "data_last_updated": ("attributes.datalastupdated", "datetime"),
        },
    },
    "training": {
        "endpoint": "/training",
        "columns": {
            **_USER_COLUMNS,
            "user_assignment_status": ("attributes.userassignmentstatus", "str"),
            "assignment_name": ("attributes.assignmentname", "str"),
            "assignment_start_date": ("attributes.assignmentstartdate", "datetime"),
            "assignment_due_date": ("attributes.assignmentduedate", "datetime"),
            "assignment_deleted_date": (
                "attributes.assignmentdeleteddate",
                "datetime",
            ),
            "assignment_status": ("attributes.assignmentstatus", "str"),
            "assignment_method": ("attributes.assignmentmethod", "str"),
            "assignment_deleted": ("attributes.assignmentdeleted", "bool"),
            "duration": ("attributes.duration", "str"),
            "auto_enroll": ("attributes.isautoenroll", "bool"),
            "module_name_admin": ("attributes.modulename_admin", "str"),
            "module_name_user": ("attributes.modulename_user", "str"),
            "module_type": ("attributes.moduletype", "str"),
            "module_attempt_date": ("attributes.moduleattemptdate", "datetime"),
            "module_last_action": ("attributes.modulelastaction", "str"),
            "seconds_in_module_attempt": (
                "attributes.secondsinmoduleattempt",
                "int",
            ),
            "module_attempt_end_status": ("attributes.moduleattemptendstatus", "str"),
            "module_attempt_status": ("attributes.moduleattemptstatus", "str"),
            "module_attempt_score": ("attributes.moduleattemptscore", "float"),
            "module_attempt_score_correct": (
                "attributes.moduleattemptscorecorrect",
                "int",
            ),
            "module_attempt_score_answered": (
                "attributes.moduleattemptscoreanswered",
                "int",
            ),
            "user_removed_from_assignment": (
                "attributes.userremovedfromassignment",
                "bool",
            ),
            "freeplay": ("attributes.isfreeplay", "bool"),
            "force_completed_date": ("attributes.forcecompleteddate", "datetime"),
        },
    },
    "phishing": {
        "endpoint": "/phishing",
        "columns": {
            **_USER_COLUMNS,
            "sent_timestamp": ("attributes.senttimestamp", "datetime"),
            "event_timestamp": ("attributes.eventtimestamp", "datetime"),
            "event_type": ("attributes.eventtype", "str"),
            "campaign_name": ("attributes.campaignname", "str"),
            "campaign_type": ("attributes.campaigntype", "str"),
            "campaign_status": ("attributes.campaignstatus", "str"),
            "campaign_start_date": ("attributes.campaignstartdate", "datetime"),
            "campaign_end_date": ("attributes.campaignenddate", "datetime"),
            "auto_enrollment": ("attributes.autoenrollment", "bool"),
            "template_name": ("attributes.templatename", "str"),
            "template_subject": ("attributes.templatesubject", "str"),
            "assessment_archived": ("attributes.assessmentisarchived", "bool"),
        },
    },
    "cyberstrength": {
        "endpoint": "/cyberstrength",
        "columns": {
            **_USER_COLUMNS,
            "assignment_name": ("attributes.assignmentname", "str"),
            "assignment_status": ("attributes.assignmentstatus", "str"),
            "assignment_start_date": ("attributes.assignmentstartdate", "datetime"),
            "assignment_due_date": ("attributes.assignmentduedate", "datetime"),
            "assignment_deleted_date": (
                "attributes.assignmentdeleteddate",
                "datetime",
            ),
            "assignment_average_score": ("attributes.assignmentaveragescore", "float"),
            "assessment_name": ("attributes.assessmentname", "str"),
            "assessment_status": ("attributes.assessmentstatus", "str"),
            "assessment_type": ("attributes.assessmenttype", "str"),
            "user_assignment_status": ("attributes.userassignmentstatus", "str"),
            "user_removed_from_assignment": (
                "attributes.userremovedfromassignment",
                "bool",
            ),
            "user_correct_on_assignment": (
                "attributes.usercorrectonassignment",
                "int",
            ),
            "user_answered_on_assignment": (
                "attributes.useransweredonassignment",
                "int",
            ),
            "user_score_on_assignment": ("attributes.userscoreonassignment", "float"),
            "company_average_score": ("attributes.companyaveragescore", "float"),
            "category": ("attributes.category", "str"),
            "category_benchmark_all": ("attributes.categorybenchmarkall", "float"),
            "category_benchmark_industry": (
                "attributes.categorybenchmarkindustry",
                "float",
            ),
            "questions_in_category": ("attributes.questionsincategory", "int"),
            "is_ae_enabled": ("attributes.isaeenabled", "bool"),
            "attempt_date": ("attributes.attemptdate", "datetime"),
            "seconds_in_attempt": ("attributes.secondsinattempt", "int"),
            "question_id": ("attributes.questionid", "str"),
            "question_type": ("attributes.questiontype", "str"),
            "question_text": ("attributes.questiontext", "str"),
            "question_date": ("attributes.questiondate", "datetime"),
            "question_latency": ("attributes.questionlatency", "int"),
            "custom_question": ("attributes.iscustomquestion", "bool"),
            "selected_answer": ("attributes.selectedanswer", "str"),
            "correct": ("attributes.correct", "bool"),
        },
    },
    "phishalarm": {
        "endpoint": "/phishalarm",
        "columns": {
            **_USER_COLUMNS,
            "campaign_name": ("attributes.campaignname", "str"),
            "action": ("attributes.action", "str"),
            "email_type": ("attributes.emailtype", "str"),
            "received_date": ("attributes.receiveddate", "datetime"),
            "reported_date": ("attributes.reporteddate", "datetime"),
            "elapsed_hours": ("attributes.elapsedhours", "float"),
            "os": ("attributes.os", "str"),
            "email_client_version": ("attributes.emailclientversion", "str"),
            "assessment_soft_deleted_date": (
                "attributes.assessmentsoftdeleteddate",
                "datetime",
            ),
        },
    },
}


class ProofpointSatCollector(Collector):
    env_prefix = "PROOFPOINT_SAT"
    display_name = "Proofpoint Security Awareness Training"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {"token": True, "region": False}

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        region = (self._config.get("region") or _DEFAULT_REGION).lower()
        if region not in _REGION_HOSTS:
            raise ValueError(
                f"Unknown Proofpoint SAT region '{region}': expected one of "
                f"{', '.join(_REGION_HOSTS)} (config 'region' or env var "
                "PROOFPOINT_SAT_REGION)"
            )
        self._base_url = f"https://{_REGION_HOSTS[region]}{_API_ROOT}"

    def _authenticate(self) -> None:
        self._session.headers["x-apikey-token"] = self._config["token"]
        self._session.headers["Accept"] = "application/json"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        page = cursor if cursor is not None else 1
        params: dict[str, Any] = {
            "page[number]": page,
            "page[size]": _PAGE_SIZE,
            "user_tag_enable": "TRUE",
        }
        params.update(kwargs)

        body = self._get(self.manifest[resource]["endpoint"], params).json()
        records = body.get("data") or []
        if not records:
            return [], None

        count = (body.get("meta") or {}).get("count")
        has_more = bool((body.get("links") or {}).get("next")) or (
            count is not None and page * int(params["page[size]"]) < int(count)
        )
        return records, page + 1 if has_more else None

    def _get(self, endpoint: str, params: dict[str, Any]) -> Any:
        response = self._session.get(
            self._base_url + endpoint, params=params, timeout=60
        )
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
                extra={"source": "proofpoint_sat", "status_code": response.status_code},
            )
        response.raise_for_status()
        return response
