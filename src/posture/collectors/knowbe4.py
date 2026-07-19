"""KnowBe4 Security Awareness Training collector.

Raw ``requests`` against the KnowBe4 API v1 — no vendor SDK. Auth, retry
(429/401/connection-error), and reporting come from the base Collector.
Pagination is KnowBe4's plain ``page``/``per_page`` scheme: keep requesting
the next page until a short page comes back.

Resources: ``training_enrollments``.
"""

from __future__ import annotations

import os
from typing import Any

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger_name = "posture.knowbe4"

_REGION_BASE_URLS = {
    "us": "https://us.api.knowbe4.com",
    "eu": "https://eu.api.knowbe4.com",
}
_DEFAULT_REGION = "us"
_PAGE_SIZE = 500

MANIFEST: dict[str, dict[str, Any]] = {
    "training_enrollments": {
        "endpoint": "/v1/training/enrollments",
        "columns": {
            "enrollment_id": ("enrollment_id", "int"),
            "user_id": ("user.id", "int"),
            "user_email": ("user.email", "str"),
            "user_first_name": ("user.first_name", "str"),
            "user_last_name": ("user.last_name", "str"),
            "content_type": ("content_type", "str"),
            "module_name": ("module_name", "str"),
            "campaign_name": ("campaign_name", "str"),
            "enrollment_date": ("enrollment_date", "datetime"),
            "start_date": ("start_date", "datetime"),
            "completion_date": ("completion_date", "datetime"),
            "status": ("status", "str"),
            "time_spent": ("time_spent", "int"),
        },
    },
}


class Knowbe4Collector(Collector):
    env_prefix = "KNOWBE4"
    manifest = MANIFEST
    required_config_keys = ("api_token",)

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        region = (
            (config or {}).get("region")
            or os.environ.get("KNOWBE4_REGION")
            or _DEFAULT_REGION
        )
        self._base_url = _REGION_BASE_URLS.get(
            region, _REGION_BASE_URLS[_DEFAULT_REGION]
        )

    def _authenticate(self) -> None:
        self._session.headers["Authorization"] = f"Bearer {self._config['api_token']}"
        self._session.headers["Accept"] = "application/json"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        page = cursor if cursor is not None else 1
        endpoint = self.manifest[resource]["endpoint"]
        params: dict[str, Any] = {"page": page, "per_page": _PAGE_SIZE}
        params.update(kwargs)

        response = self._session.get(
            self._base_url + endpoint, params=params, timeout=30
        )
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitedSignal(
                retry_after=float(retry_after) if retry_after else None
            )
        if response.status_code == 401:
            raise UnauthorizedSignal()
        response.raise_for_status()

        records: list[dict[str, Any]] = response.json()
        next_cursor = page + 1 if len(records) == _PAGE_SIZE else None
        return records, next_cursor
