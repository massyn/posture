"""Rapid7 InsightVM (cloud) collector.

Raw ``requests`` against the Rapid7 Insight Platform's cloud VM API
(``https://<region>.api.insight.rapid7.com/vm/v4/integration/...``) — no
vendor SDK. This targets the **cloud** platform, not the on-premise
Security Console API v3 (``https://<console>:3780/api/3``, HTTP basic auth),
which is a different product surface entirely.

Auth is a static Insight platform API key sent as the ``X-Api-Key`` header
— no token exchange. The region (``us``, ``eu``, ``ca``, ``au``, ``ap``)
selects the API host and is required config, since a key issued in one
region's console does not resolve in another; an explicit ``endpoint``
override is also accepted for tenants on a non-standard host.

Two pagination shapes, both with a ``{"data": [...], "metadata": {...}}``
envelope:

- ``assets`` is a ``POST`` search (empty body = all assets) paginated by an
  opaque ``cursor`` echoed back in ``metadata.cursor`` — absent means the
  last page.
- ``vulnerabilities`` is a ``GET`` paginated by ``page`` number against
  ``metadata.totalPages``.

Resources: ``assets``, ``vulnerabilities``.

**Caveat:** ``MANIFEST`` column paths and the pagination details below were
built from Rapid7's public API reference, not a live schema introspection
against a real tenant — a stronger caveat than ``wiz.py``'s, since the v4
integration API's response envelope and field casing are only partially
documented. Verify field names/nesting and that pagination terminates
against a real tenant before relying on this collector.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal
from posture.exceptions import AuthenticationError

logger = logging.getLogger("posture.collectors.rapid7_insightvm")

_PAGE_SIZE = 500
_DEFAULT_REGION = "us"
_VALID_REGIONS = ("us", "us2", "us3", "eu", "ca", "au", "ap")

_ASSETS_PATH = "/vm/v4/integration/assets"
_VULNERABILITIES_PATH = "/vm/v4/integration/vulnerabilities"

MANIFEST: dict[str, dict[str, Any]] = {
    "assets": {
        "endpoint": _ASSETS_PATH,
        "columns": {
            "id": ("id", "str"),
            "ip": ("ip", "str"),
            "mac": ("mac", "str"),
            "host_name": ("host_name", "str"),
            "os_name": ("os_name", "str"),
            "os_version": ("os_version", "str"),
            "os_type": ("os_type", "str"),
            "os_vendor": ("os_vendor", "str"),
            "assessed_for_vulnerabilities": (
                "assessed_for_vulnerabilities",
                "bool",
            ),
            "assessed_for_policies": ("assessed_for_policies", "bool"),
            "risk_score": ("risk_score", "float"),
            "critical_vulnerabilities": ("critical_vulnerabilities", "int"),
            "severe_vulnerabilities": ("severe_vulnerabilities", "int"),
            "moderate_vulnerabilities": ("moderate_vulnerabilities", "int"),
            "total_vulnerabilities": ("vulnerabilities", "int"),
            "exploits": ("exploits", "int"),
            "malware_kits": ("malware_kits", "int"),
            "last_assessed_for_vulnerabilities": (
                "last_assessed_for_vulnerabilities",
                "datetime",
            ),
            "tags": ("tags", "json"),
            "addresses": ("addresses", "json"),
            "host_names": ("host_names", "json"),
        },
    },
    "vulnerabilities": {
        "endpoint": _VULNERABILITIES_PATH,
        "columns": {
            "id": ("id", "str"),
            "title": ("title", "str"),
            "description": ("description", "str"),
            "severity": ("severity", "str"),
            "severity_score": ("severity_score", "int"),
            "risk_score": ("risk_score", "float"),
            "cvss_v2_score": ("cvss_v2_score", "float"),
            "cvss_v2_vector": ("cvss_v2_vector", "str"),
            "cvss_v3_score": ("cvss_v3_score", "float"),
            "cvss_v3_vector": ("cvss_v3_vector", "str"),
            "denial_of_service": ("denial_of_service", "bool"),
            "exploits": ("exploits", "int"),
            "malware_kits": ("malware_kits", "int"),
            "published": ("published", "datetime"),
            "added": ("added", "datetime"),
            "modified": ("modified", "datetime"),
            "categories": ("categories", "json"),
            "cves": ("cves", "json"),
            "references": ("references", "json"),
        },
    },
}


class Rapid7InsightVMCollector(Collector):
    env_prefix = "RAPID7_INSIGHTVM"
    display_name = "Rapid7 InsightVM"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {
        "api_key": True,
        "region": False,
        "endpoint": False,
    }
    url_config_keys = ("endpoint",)

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        endpoint = self._config.get("endpoint")
        if endpoint:
            self._base_url = endpoint
        else:
            region = (self._config.get("region") or _DEFAULT_REGION).lower()
            if region not in _VALID_REGIONS:
                raise ValueError(
                    f"Unknown Rapid7 region '{region}'. "
                    f"Expected one of {_VALID_REGIONS} or set RAPID7_INSIGHTVM_ENDPOINT"
                )
            self._base_url = f"https://{region}.api.insight.rapid7.com"

    def _authenticate(self) -> None:
        self._session.headers["Accept"] = "application/json"
        self._session.headers["Content-Type"] = "application/json"
        self._session.headers["X-Api-Key"] = self._config["api_key"]
        response = self._session.get(
            f"{self._base_url}{_VULNERABILITIES_PATH}",
            params={"page": 0, "size": 1},
            timeout=30,
        )
        if response.status_code in (401, 403):
            raise AuthenticationError(
                "Rapid7 rejected the Insight platform API key",
                source="rapid7_insightvm",
                hint="check RAPID7_INSIGHTVM_API_KEY and RAPID7_INSIGHTVM_REGION",
            )

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "assets":
            return self._fetch_assets_page(kwargs, cursor)
        if resource == "vulnerabilities":
            return self._fetch_vulnerabilities_page(kwargs, cursor)
        raise ValueError(f"Unsupported resource '{resource}'")

    def _fetch_assets_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        params: dict[str, Any] = {"size": _PAGE_SIZE}
        if cursor is not None:
            params["cursor"] = cursor
        body = {k: v for k, v in kwargs.items() if k != "max_workers"}
        payload = self._request("POST", _ASSETS_PATH, params=params, json_body=body)
        records = payload.get("data", []) or []
        next_cursor = (payload.get("metadata") or {}).get("cursor")
        return records, next_cursor or None

    def _fetch_vulnerabilities_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        page = int(cursor) if cursor is not None else 0
        params: dict[str, Any] = {"page": page, "size": _PAGE_SIZE}
        params.update(kwargs)
        payload = self._request("GET", _VULNERABILITIES_PATH, params=params)
        records = payload.get("data", []) or []
        metadata = payload.get("metadata") or {}
        total_pages = metadata.get("totalPages", page + 1)
        next_cursor = page + 1 if page + 1 < total_pages else None
        return records, next_cursor

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        response = self._session.request(
            method,
            f"{self._base_url}{path}",
            params=params,
            json=json_body if method == "POST" else None,
            timeout=60,
        )
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
                    "source": "rapid7_insightvm",
                    "status_code": response.status_code,
                },
            )
        response.raise_for_status()
        return response.json()
