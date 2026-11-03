"""Qualys Global AssetView / CyberSecurity Asset Management tables.

Raw ``requests`` against the CSAM asset search API
(``POST /rest/2.0/search/am/asset``), no vendor SDK. GAV and CSAM share this
API; Qualys positions it as the replacement for the legacy Asset Management
(AM) search. It lives on the subscription's *gateway* host
(``https://gateway.qgN.apps.qualys.com``), not the ``qualysapi`` host the
other Qualys tables use, and authenticates with a JWT rather than Basic auth.

Gateway host, JWT auth and response checks are shared with Container
Security; see ``gateway.py``.

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

from typing import Any

import requests

from posture.collectors.qualys.gateway import GatewayAuth

_ASSET_SEARCH_PATH = "/rest/2.0/search/am/asset"
_PAGE_SIZE = 300
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


class AssetsApi:
    resources = ("assets",)

    def __init__(self, session: requests.Session, gateway: GatewayAuth) -> None:
        self._session = session
        self._gateway = gateway

    def fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
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
            self._gateway.url + _ASSET_SEARCH_PATH,
            params=params,
            json={"filters": filters} if filters else None,
            headers=self._gateway.headers(),
            timeout=_REQUEST_TIMEOUT_SECONDS,
        )
        self._gateway.check(response, resource)

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
