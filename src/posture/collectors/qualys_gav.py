"""Qualys Global AssetView / CyberSecurity Asset Management collector.

Raw ``requests`` against the CSAM asset search API
(``POST /rest/2.0/search/am/asset``), no vendor SDK. GAV and CSAM share this
API; Qualys positions it as the replacement for the legacy Asset Management
(AM) search. It lives on the subscription's *gateway* host
(``https://gateway.qgN.apps.qualys.com``), not the ``qualysapi`` host
``qualys.py`` uses, and authenticates with a JWT rather than Basic auth — a
third Qualys API family, hence its own collector and ``QUALYS_GAV_*`` config.

Auth: ``POST {gateway_url}/auth`` with the username/password form fields and
``token=true`` returns the JWT as the plain-text body, sent thereafter as
``Authorization: Bearer <jwt>``. Tokens last four hours, so ``_authenticate``
sets ``_token_expires_at`` and the base class refreshes ahead of expiry on
long runs; a 401 mid-run re-authenticates via the usual ``UnauthorizedSignal``.

Pagination: ``pageSize`` (max 300) and ``lastSeenAssetId``; each response
carries ``hasMore`` (1/0) and the ``lastSeenAssetId`` to resume from, which
becomes the cursor.

``asset_software`` and ``asset_open_ports`` are derived from ``assets``'
nested ``softwareListData.software`` / ``openPortListData.openPort`` lists —
no extra requests, but ``assets``' raw records are cached to disk for the
second and third resource to replay.

kwargs: ``filters`` — a list of CSAM criteria dicts (``{"field": ...,
"operator": ..., "value": ...}``) sent as the JSON filter body, passed through
verbatim; ``asset_last_updated`` — an ``assetLastUpdated`` UTC timestamp
(``yyyy-MM-ddTHH:mmZ``) returning only assets updated since.

**Caveat:** built from Qualys's public CSAM API documentation and release
notes; no live subscription was available. The asset-level fields come from
documented samples, but the nested ``softwareListData``/``openPortListData``
field names are the least certain part, and whether the free GAV tier (rather
than paid CSAM) is granted this API isn't stated by Qualys. Verify against a
real subscription before relying on it.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar

import requests

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal
from posture.exceptions import AuthenticationError

logger = logging.getLogger("posture.collectors.qualys_gav")

_AUTH_PATH = "/auth"
_ASSET_SEARCH_PATH = "/rest/2.0/search/am/asset"
_PAGE_SIZE = 300
_TOKEN_LIFETIME = timedelta(hours=4)
_REQUEST_TIMEOUT_SECONDS = 300

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
            "address": ("address", "str"),
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
    "asset_software": {
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
    "asset_open_ports": {
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


class QualysGavCollector(Collector):
    env_prefix = "QUALYS_GAV"
    display_name = "Qualys Global AssetView"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {
        "username": True,
        "password": True,
        "gateway_url": True,
    }
    url_config_keys: tuple[str, ...] = ("gateway_url",)

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        self._base_url = self._config["gateway_url"]

    def _authenticate(self) -> None:
        response = self._session.post(
            self._base_url + _AUTH_PATH,
            data={
                "username": self._config["username"],
                "password": self._config["password"],
                "token": "true",
            },
            headers={"X-Requested-With": "posture"},
            timeout=60,
        )
        if response.status_code in (400, 401, 403):
            raise AuthenticationError(
                f"Qualys gateway authentication failed (HTTP {response.status_code})",
                source="qualys_gav",
                hint="check QUALYS_GAV_USERNAME/QUALYS_GAV_PASSWORD and that "
                "QUALYS_GAV_GATEWAY_URL is the subscription's gateway host",
            )
        response.raise_for_status()
        self._session.headers["Authorization"] = f"Bearer {response.text.strip()}"
        self._session.headers["Accept"] = "application/json"
        self._token_expires_at = datetime.now(timezone.utc) + _TOKEN_LIFETIME

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource != "assets":
            raise ValueError(f"Unsupported resource '{resource}'")
        unknown = set(kwargs) - {"filters", "asset_last_updated"}
        if unknown:
            raise ValueError(f"Unsupported kwargs for '{resource}': {sorted(unknown)}")

        params: dict[str, Any] = {"pageSize": _PAGE_SIZE}
        if cursor is not None:
            params["lastSeenAssetId"] = cursor
        if "asset_last_updated" in kwargs:
            params["assetLastUpdated"] = kwargs["asset_last_updated"]
        filters = kwargs.get("filters")

        response = self._session.post(
            self._base_url + _ASSET_SEARCH_PATH,
            params=params,
            json={"filters": filters} if filters else None,
            timeout=_REQUEST_TIMEOUT_SECONDS,
        )
        if response.status_code == 429:
            wait = response.headers.get(
                "X-RateLimit-ToWait-Sec"
            ) or response.headers.get("Retry-After")
            raise RateLimitedSignal(retry_after=float(wait) if wait else None)
        if response.status_code == 401:
            raise UnauthorizedSignal()
        response.raise_for_status()

        body = response.json()
        if body.get("responseCode") != "SUCCESS":
            raise requests.HTTPError(
                f"Qualys GAV returned {body.get('responseCode')} for '{resource}': "
                f"{body.get('responseMessage', '')}",
                response=response,
            )
        records = (body.get("assetListData") or {}).get("asset") or []
        if str(body.get("hasMore")) != "1":
            return records, None
        last_seen = body.get("lastSeenAssetId")
        if last_seen is None:
            # Ending here would silently hand back a partial snapshot.
            raise ValueError("Qualys GAV reported more assets but no lastSeenAssetId")
        return records, last_seen
