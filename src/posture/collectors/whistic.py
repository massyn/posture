"""Whistic collector.

Raw ``requests`` against Whistic's Public API (``/api/v3/...`` under
``https://public.whistic.com/api``) — no vendor SDK. Static token auth via
the ``api-key`` header (same "just set the header" shape as AppOmni/Snyk/
UpGuard, no OAuth flow).

Pagination is cursor-based: ``GET /vendors`` takes ``cursor``/``page_size``
query params and returns a bare JSON array (no envelope, no ``next`` link,
no total count). The OpenAPI spec describes ``cursor`` as "begin with the
vendor that comes after the specified one" without naming what value to
pass — the only id-shaped field on a returned vendor is its own
``identifier``, so ``_fetch_page`` threads the last record's ``identifier``
through as the next cursor and stops once a page comes back shorter than
``page_size`` (the same short-page heuristic ``knowbe4.py`` used before its
own cursor migration). **Not verified against a live tenant** — same caveat
as ``wiz.py``/``appomni.py``/etc., but doubly so here since the cursor
semantics themselves are inferred rather than confirmed; verify pagination
actually terminates before relying on this collector at scale.

``vendor_details`` fans out one ``GET /vendors/{identifier}`` per id across
a thread pool, ids read from ``vendors`` internally unless a ``vendor_ids``
kwarg is given — the same per-item fan-out shape as ``appomni.py``'s
``policy_risk_summary``. The list endpoint (``VendorPreview``) only carries
summary fields; contract/financial/contact/risk detail only exists on the
single-object endpoint (``Vendor``).

Resources: ``vendors``, ``vendor_details``. Whistic's write endpoints
(``vendors.update``/``.new``, vendor intake form submission) are
intentionally out of scope — posture is a read-only collection library.
"""

from __future__ import annotations

import concurrent.futures
import logging
from typing import Any

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger = logging.getLogger("posture.collectors.whistic")

_DEFAULT_ENDPOINT = "https://public.whistic.com/api"
_VENDORS_PATH = "/vendors"
_VENDOR_DETAIL_PATH = "/vendors/{identifier}"

_MAX_PAGE_SIZE = 100
_VENDOR_DETAILS_MAX_WORKERS = 10

MANIFEST: dict[str, dict[str, Any]] = {
    "vendors": {
        # VendorPreview — the catalog list view. Detail-only fields
        # (description, contract/billing, contacts, business unit, notes,
        # custom attributes) live on vendor_details.
        "endpoint": _VENDORS_PATH,
        "columns": {
            "identifier": ("identifier", "str"),
            "name": ("name", "str"),
            "url": ("url", "str"),
            "service": ("service", "str"),
            "status": ("status", "str"),
            "assessment_progress": ("assessment_progress", "str"),
            "questionnaire_progress": ("questionnaire_progress", "str"),
            "created_date": ("created_date", "datetime"),
            "score": ("score.overall_score", "int"),
            "score_rating": ("score.rating", "str"),
            "inherent_risk": ("inherent_risk.name", "str"),
            "residual_risk": ("residual_risk.name", "str"),
            "criticality": ("criticality.name", "str"),
        },
    },
    "vendor_details": {
        # Fan-out resource: one GET /vendors/{identifier} per vendors row,
        # because contract/billing/contact/business-unit/risk detail only
        # exists on the single-object view (see module docstring).
        "endpoint": _VENDOR_DETAIL_PATH,
        "columns": {
            "identifier": ("identifier", "str"),
            "name": ("name", "str"),
            "url": ("url", "str"),
            "service": ("service", "str"),
            "status": ("status", "str"),
            "description": ("description", "str"),
            "created_date": ("created_date", "datetime"),
            "last_modified_date": ("last_modified_date", "datetime"),
            "assessment_progress": ("assessment_progress", "str"),
            "questionnaire_progress": ("questionnaire_progress", "str"),
            "internal_users": ("internal_users", "str"),
            "contract_value": ("contract_value", "str"),
            "billing_terms": ("billing_terms", "str"),
            "payment_cadence": ("payment_cadence", "str"),
            "payment_method": ("payment_method", "str"),
            "contract_start_date": ("contract_start_date", "datetime"),
            "contract_end_date": ("contract_end_date", "datetime"),
            "billing_address_city": ("billing_address.city", "str"),
            "billing_address_state": ("billing_address.state", "str"),
            "billing_address_country": ("billing_address.country", "str"),
            "criticality": ("criticality.name", "str"),
            "business_unit": ("business_unit.name", "str"),
            "inherent_risk": ("inherent_risk.name", "str"),
            "residual_risk": ("residual_risk.name", "str"),
            "renewal_frequency": ("renewal.frequency", "int"),
            "renewal_cadence": ("renewal.cadence", "str"),
            "renewal_next_questionnaire_date": (
                "renewal.next_questionnaire_date",
                "datetime",
            ),
            "score": ("score.overall_score", "int"),
            "score_rating": ("score.rating", "str"),
            "enable_smart_search": ("enable_smart_search", "bool"),
            "external_contacts": ("external_contacts", "json"),
            "internal_contacts": ("internal_contacts", "json"),
            "internal_systems": ("internal_systems", "json"),
            "data_types": ("data_types", "json"),
            "notes": ("notes", "json"),
            "custom_attributes": ("custom_attributes", "json"),
        },
    },
}


class WhisticCollector(Collector):
    env_prefix = "WHISTIC"
    display_name = "Whistic"
    manifest = MANIFEST
    required_config_keys = ("token",)

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        endpoint = (config or {}).get("endpoint") or _DEFAULT_ENDPOINT
        self._base_url = self._normalize_url(endpoint)

    def _authenticate(self) -> None:
        self._session.headers["Accept"] = "application/json"
        self._session.headers["Content-Type"] = "application/json"
        self._session.headers["api-key"] = self._config["token"]

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "vendor_details":
            return self._fetch_vendor_details(kwargs, cursor)
        return self._fetch_vendors_page(kwargs, cursor)

    def _fetch_vendors_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        page_size = kwargs.get("page_size", _MAX_PAGE_SIZE)
        params: dict[str, Any] = {"page_size": page_size}
        if cursor is not None:
            params["cursor"] = cursor
        params.update({k: v for k, v in kwargs.items() if k != "page_size"})

        records = self._get(self._base_url + _VENDORS_PATH, params).json()
        next_cursor = records[-1]["identifier"] if len(records) == page_size else None
        return records, next_cursor

    def _fetch_vendor_details(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None  # entire fan-out already completed on first call

        vendor_ids = kwargs.get("vendor_ids")
        if vendor_ids is None:
            raw_vendors = self._get_raw("vendors", {})
            vendor_ids = [
                v["identifier"] for v in raw_vendors if v.get("identifier") is not None
            ]
        if not vendor_ids:
            return [], None

        max_workers = kwargs.get("max_workers", _VENDOR_DETAILS_MAX_WORKERS)
        workers = max(1, min(max_workers, len(vendor_ids)))

        records: list[dict[str, Any]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(self._fetch_vendor_detail, vendor_id)
                for vendor_id in vendor_ids
            ]
            for future in concurrent.futures.as_completed(futures):
                records.append(future.result())

        return records, None

    def _fetch_vendor_detail(self, vendor_id: Any) -> dict[str, Any]:
        path = _VENDOR_DETAIL_PATH.format(identifier=vendor_id)
        return self._get(self._base_url + path).json()

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
                extra={"source": "whistic", "status_code": response.status_code},
            )
        response.raise_for_status()
        return response
