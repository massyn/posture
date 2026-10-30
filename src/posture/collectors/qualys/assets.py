"""Qualys Global AssetView / CyberSecurity Asset Management tables.

Raw ``requests`` against the CSAM asset search API
(``POST /rest/2.0/search/am/asset``), no vendor SDK. GAV and CSAM share this
API; Qualys positions it as the replacement for the legacy Asset Management
(AM) search. It lives on the subscription's *gateway* host
(``https://gateway.qgN.apps.qualys.com``), not the ``qualysapi`` host the
other Qualys tables use, and authenticates with a JWT rather than Basic auth.

Gateway: ``gateway_url`` when configured, otherwise derived from ``base_url``
by ``gateway_url_for`` (every public platform's gateway follows its API
server's host). A ``base_url`` that doesn't follow the pattern (a private
cloud platform) fails only these tables, asking for ``QUALYS_GATEWAY_URL``.

Auth: ``POST {gateway_url}/auth`` with the username/password form fields and
``token=true`` returns the JWT as the plain-text body, sent as
``Authorization: Bearer <jwt>``. The token is fetched lazily on the first
asset request, so a subscription without CSAM never logs in to the gateway
and the other Qualys tables are unaffected. Tokens last four hours and are
refreshed ahead of expiry; a 401 mid-run drops the token and raises
``UnauthorizedSignal``, so the base class's retry fetches a fresh one. A 401
from ``/auth`` itself is ``CredentialsRejected`` (the username or password is
wrong for every Qualys table); a 400 or 403 there fails only these tables.

Pagination: ``pageSize`` (max 300) and ``lastSeenAssetId``; each response
carries ``hasMore`` (1/0) and the ``lastSeenAssetId`` to resume from, which
becomes the cursor.

``assets_software`` and ``assets_open_ports`` are derived from ``assets``'
nested ``softwareListData.software`` / ``openPortListData.openPort`` lists:
no extra requests, but ``assets``' raw records are cached to disk for the
derived tables to replay.

kwargs: ``filters``, a list of CSAM criteria dicts (``{"field": ...,
"operator": ..., "value": ...}``) sent as the JSON filter body, passed through
verbatim; ``asset_last_updated``, an ``assetLastUpdated`` UTC timestamp
(``yyyy-MM-ddTHH:mmZ``) returning only assets updated since.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

import requests

from posture.base import RateLimitedSignal, UnauthorizedSignal
from posture.collectors.qualys.errors import CredentialsRejected
from posture.exceptions import AuthenticationError

_AUTH_PATH = "/auth"
_ASSET_SEARCH_PATH = "/rest/2.0/search/am/asset"
_PAGE_SIZE = 300
_TOKEN_LIFETIME = timedelta(hours=4)
# Refresh this long before expiry, so a request in flight doesn't race the
# token dying mid-call.
_TOKEN_REFRESH_MARGIN = timedelta(minutes=5)
_REQUEST_TIMEOUT_SECONDS = 300

# The two oldest platforms' API servers predate the qgN naming; their
# gateways don't.
_LEGACY_GATEWAYS = {
    "qualysapi.qualys.com": "gateway.qg1.apps.qualys.com",
    "qualysapi.qualys.eu": "gateway.qg1.apps.qualys.eu",
}

_ASSET_PARENT_COLUMNS: dict[str, tuple] = {
    "asset_id": ("$parent.assetId", "str"),
    "host_id": ("$parent.hostId", "str"),
    "asset_name": ("$parent.assetName", "str"),
}

MANIFEST: dict[str, dict[str, Any]] = {
    "assets": {
        "endpoint": _ASSET_SEARCH_PATH,
        "columns": {
            "asset_id": ("assetId", "str"),
            "asset_uuid": ("assetUUID", "str"),
            "host_id": ("hostId", "str"),
            "asset_name": ("assetName", "str"),
            "asset_type": ("assetType", "str"),
            "ip": ("address", "str"),
            "dns_name": ("dnsName", "str"),
            "netbios_name": ("netbiosName", "str"),
            "os_name": ("operatingSystem.osName", "str"),
            "os_full_name": ("operatingSystem.fullName", "str"),
            "os_category": ("operatingSystem.category", "str"),
            "hardware_full_name": ("hardware.fullName", "str"),
            "hardware_manufacturer": ("hardware.manufacturer", "str"),
            "hardware_model": ("hardware.model", "str"),
            "last_logged_on_user": ("lastLoggedOnUser", "str"),
            "last_boot": ("lastBoot", "datetime"),
            "agent_version": ("agent.version", "str"),
            "agent_status": ("agent.status", "str"),
            "sensor_modules": ("sensor.activatedForModules", "json"),
            "last_vm_scan": ("sensor.lastVMScan", "datetime"),
            "last_full_scan": ("sensor.lastFullScan", "datetime"),
            "criticality_score": ("criticality.score", "int"),
            "risk_score": ("riskScore", "int"),
            "tags": ("tagList.tag", "json"),
            "created": ("inventory.created", "datetime"),
            "last_updated": ("inventory.lastUpdated", "datetime"),
        },
    },
    "assets_software": {
        "derived_from": "assets",
        "record_path": "softwareListData.software",
        "columns": {
            **_ASSET_PARENT_COLUMNS,
            "software_id": ("id", "str"),
            "full_name": ("fullName", "str"),
            "product": ("product", "str"),
            "version": ("version", "str"),
            "publisher": ("publisher", "str"),
            "category": ("category", "str"),
        },
    },
    "assets_open_ports": {
        "derived_from": "assets",
        "record_path": "openPortListData.openPort",
        "columns": {
            **_ASSET_PARENT_COLUMNS,
            "port": ("port", "int"),
            "protocol": ("protocol", "str"),
            "detected_service": ("detectedService", "str"),
            "first_found": ("firstFound", "datetime"),
            "last_updated": ("lastUpdated", "datetime"),
        },
    },
}


def gateway_url_for(base_url: str) -> str | None:
    """The gateway URL matching an API server URL, or None when ``base_url``
    doesn't follow Qualys's public platform naming."""
    host = urlparse(base_url).hostname or ""
    gateway = _LEGACY_GATEWAYS.get(host)
    if gateway is None and host.startswith("qualysapi."):
        gateway = "gateway." + host.removeprefix("qualysapi.")
    return f"https://{gateway}" if gateway else None


class AssetsApi:
    resources = ("assets",)

    def __init__(
        self,
        session: requests.Session,
        gateway_url: str | None,
        credentials: tuple[str, str],
    ) -> None:
        self._session = session
        self._gateway_url = gateway_url
        self._credentials = credentials
        self._token: str | None = None
        self.token_expires_at: datetime | None = None

    def fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        unknown = set(kwargs) - {"filters", "asset_last_updated"}
        if unknown:
            raise ValueError(f"Unsupported kwargs for '{resource}': {sorted(unknown)}")
        if self._gateway_url is None:
            raise ValueError(
                "Qualys gateway URL could not be derived from QUALYS_BASE_URL; "
                "set QUALYS_GATEWAY_URL to the subscription's gateway host"
            )

        params: dict[str, Any] = {"pageSize": _PAGE_SIZE}
        if cursor is not None:
            params["lastSeenAssetId"] = cursor
        if "asset_last_updated" in kwargs:
            params["assetLastUpdated"] = kwargs["asset_last_updated"]
        filters = kwargs.get("filters")

        response = self._session.post(
            self._gateway_url + _ASSET_SEARCH_PATH,
            params=params,
            json={"filters": filters} if filters else None,
            headers={
                "Authorization": f"Bearer {self._bearer_token()}",
                "Accept": "application/json",
            },
            timeout=_REQUEST_TIMEOUT_SECONDS,
        )
        if response.status_code == 429:
            wait = response.headers.get(
                "X-RateLimit-ToWait-Sec"
            ) or response.headers.get("Retry-After")
            raise RateLimitedSignal(retry_after=float(wait) if wait else None)
        if response.status_code == 401:
            self._token = None
            raise UnauthorizedSignal()
        response.raise_for_status()

        body = response.json()
        if body.get("responseCode") != "SUCCESS":
            raise requests.HTTPError(
                f"Qualys CSAM returned {body.get('responseCode')} for '{resource}': "
                f"{body.get('responseMessage', '')}",
                response=response,
            )
        records = (body.get("assetListData") or {}).get("asset") or []
        if str(body.get("hasMore")) != "1":
            return records, None
        last_seen = body.get("lastSeenAssetId")
        if last_seen is None:
            # Ending here would silently hand back a partial snapshot.
            raise ValueError("Qualys CSAM reported more assets but no lastSeenAssetId")
        return records, last_seen

    def _bearer_token(self) -> str:
        if (
            self._token is not None
            and self.token_expires_at is not None
            and datetime.now(timezone.utc)
            < self.token_expires_at - _TOKEN_REFRESH_MARGIN
        ):
            return self._token

        username, password = self._credentials
        response = self._session.post(
            self._gateway_url + _AUTH_PATH,
            data={"username": username, "password": password, "token": "true"},
            timeout=60,
        )
        if response.status_code in (400, 401, 403):
            error = (
                CredentialsRejected
                if response.status_code == 401
                else AuthenticationError
            )
            raise error(
                f"Qualys gateway authentication failed (HTTP {response.status_code})",
                source="qualys",
                hint="check QUALYS_USERNAME/QUALYS_PASSWORD, that the user has "
                "API access to CSAM/Global AssetView, and that the gateway URL "
                "(QUALYS_GATEWAY_URL, or derived from QUALYS_BASE_URL) is the "
                "subscription's gateway host",
            )
        response.raise_for_status()
        self._token = response.text.strip()
        self.token_expires_at = datetime.now(timezone.utc) + _TOKEN_LIFETIME
        return self._token
