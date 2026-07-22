"""PhriendlyPhishing collector.

Raw ``requests`` against PhriendlyPhishing's REST API v0.1 — no vendor SDK.
Auth is OAuth2 client-credentials (POST ``client_id``/``client_secret`` as a
JSON body, not form-encoded, to a dedicated auth host separate from the API
host — the same "auth host differs from API host" shape as Wiz, just without
Wiz's regional discovery). Pagination is a plain ``page``/``page_size``
scheme: keep requesting the next page until a short page comes back, the
same shape as ``knowbe4.py``'s list resources.

``clicks`` additionally takes a server-side ``start_time``/``end_time`` date
range (``YYYY-MM-DD``); this collector defaults it to the trailing 366 days
plus one day forward (mirroring the reference implementation) but kwargs win
over that default per the locked "kwargs override collector defaults" rule.

Resources: ``trainings``, ``clicks``.

**Caveat:** ``MANIFEST`` column paths below were built from the reference
extraction script this collector was ported from, not a live schema
introspection against a real tenant — same caveat as ``wiz.py``,
``appomni.py``, ``snyk.py``, ``cloudflare.py``, and ``dnsimple.py``. Verify
field names/nesting against a real tenant's response before relying on this
collector, and correct ``MANIFEST`` if they don't match.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal
from posture.exceptions import AuthenticationError

logger = logging.getLogger("posture.collectors.phriendly_phishing")

_AUTH_URL = "https://auth.api.phriendlyphishing.com/token"
_BASE_URL = "https://api.phriendlyphishing.com/v0.1"
_TRAININGS_PATH = "/trainings"
_CLICKS_PATH = "/clicks"
_PAGE_SIZE = 500
_CLICKS_LOOKBACK_DAYS = 366
_CLICKS_LOOKAHEAD_DAYS = 1

MANIFEST: dict[str, dict[str, Any]] = {
    "trainings": {
        "endpoint": _TRAININGS_PATH,
        "columns": {
            "id": ("id", "str"),
            "user_id": ("user_id", "str"),
            "email": ("email", "str"),
            "first_name": ("first_name", "str"),
            "last_name": ("last_name", "str"),
            "group": ("group", "str"),
            "training_name": ("training_name", "str"),
            "status": ("status", "str"),
            "assigned_date": ("assigned_date", "datetime"),
            "started_date": ("started_date", "datetime"),
            "completed_date": ("completed_date", "datetime"),
            "score": ("score", "float"),
        },
    },
    "clicks": {
        "endpoint": _CLICKS_PATH,
        "columns": {
            "id": ("id", "str"),
            "user_id": ("user_id", "str"),
            "email": ("email", "str"),
            "first_name": ("first_name", "str"),
            "last_name": ("last_name", "str"),
            "group": ("group", "str"),
            "campaign_name": ("campaign_name", "str"),
            "template_name": ("template_name", "str"),
            "sent_date": ("sent_date", "datetime"),
            "clicked_date": ("clicked_date", "datetime"),
            "reported_date": ("reported_date", "datetime"),
            "ip_address": ("ip_address", "str"),
            "browser": ("browser", "str"),
            "operating_system": ("operating_system", "str"),
        },
    },
}


class PhriendlyPhishingCollector(Collector):
    env_prefix = "PHRIENDLY_PHISHING"
    display_name = "PhriendlyPhishing"
    manifest = MANIFEST
    required_config_keys = ("client_id", "client_secret")

    def _authenticate(self) -> None:
        response = self._session.post(
            _AUTH_URL,
            json={
                "client_id": self._config["client_id"],
                "client_secret": self._config["client_secret"],
            },
            timeout=30,
        )
        if response.status_code == 401:
            raise AuthenticationError(
                "PhriendlyPhishing rejected the client credentials",
                source="phriendly_phishing",
                hint="check PHRIENDLY_PHISHING_CLIENT_ID / PHRIENDLY_PHISHING_CLIENT_SECRET",
            )
        response.raise_for_status()

        access_token = response.json().get("access_token")
        if access_token is None:
            raise AuthenticationError(
                "PhriendlyPhishing auth response had no access_token",
                source="phriendly_phishing",
                hint="check PHRIENDLY_PHISHING_CLIENT_ID / PHRIENDLY_PHISHING_CLIENT_SECRET",
            )
        self._session.headers["Authorization"] = f"Bearer {access_token}"
        self._session.headers["Accept"] = "application/json"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        page = cursor if cursor is not None else 1
        endpoint = self.manifest[resource]["endpoint"]
        params: dict[str, Any] = {"page": page, "page_size": _PAGE_SIZE}
        if resource == "clicks":
            now = datetime.now(timezone.utc)
            params["start_time"] = (
                now - timedelta(days=_CLICKS_LOOKBACK_DAYS)
            ).strftime("%Y-%m-%d")
            params["end_time"] = (
                now + timedelta(days=_CLICKS_LOOKAHEAD_DAYS)
            ).strftime("%Y-%m-%d")
        params.update(kwargs)

        records = self._get(endpoint, params).json().get("data", []) or []
        next_cursor = page + 1 if len(records) == _PAGE_SIZE else None
        return records, next_cursor

    def _get(self, endpoint: str, params: dict[str, Any]) -> Any:
        response = self._session.get(_BASE_URL + endpoint, params=params, timeout=30)
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
                    "source": "phriendly_phishing",
                    "status_code": response.status_code,
                },
            )
        response.raise_for_status()
        return response
