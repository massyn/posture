"""Tenable.sc (formerly SecurityCenter) collector.

Uses ``tenable.sc`` (pyTenable) rather than raw ``requests`` — the same
approved vendor-SDK exception as ``tenableio.py``, since Tenable.sc's analysis
API (``sc.analysis.vulns``, a job-backed export generator) is bespoke
server-side machinery the base class's generic REST pagination scaffold
can't express. ``hosts`` and ``asset_ips`` go through pytenable's raw
``sc.get(...)`` passthrough (Tenable.sc exposes this on top of the SDK,
the same call the reference extraction script this collector was ported
from used) rather than a dedicated SDK accessor, since pyTenable has no
higher-level wrapper for these two endpoints.

Resources: ``vulnerabilities``, ``hosts``, ``assets``, ``asset_ips``.

Tenable.sc has no cross-tenant discovery mechanism (unlike Tenable.io's
single shared cloud host) — ``endpoint`` (the on-prem/self-hosted Tenable.sc
URL) is required config.

``hosts`` and ``asset_ips`` are both scoped to a named asset list (Tenable.sc's
saved static/dynamic asset group), not the whole tenant — the reference
extraction script filtered to a single named list (default
``"Non Crowdstrike Assets"``) because Crowdstrike-covered hosts are already
collected via ``crowdstrike.py``. That name is a kwarg (``asset_name``),
not config, per the locked kwargs-are-vendor-query-dialect rule: it changes
*what data* is requested, not *who* is authenticating. Both resources
resolve the list name to its Tenable.sc asset id via a single ``asset``
lookup, cached per name on the instance for the collector's lifetime.

``asset_ips`` is not a ``derived_from`` of ``assets``: Tenable.sc returns
each asset list's member IPs as a blob of newline-separated IP addresses
and ranges (``viewableIPs[].ipList``) from a *separate* per-asset-id
endpoint, not a nested list of objects on the asset list response.
Expanding that blob into one row per IP happens in ``_fetch_page`` — a
fetch-time transform of raw text, not parse.py's job, in the same spirit as
``qualys.py`` converting XML into dicts before parse.py ever sees the data.

Dependencies
------------
    pip install "posture[tenablesc]"

**Caveat:** ``MANIFEST`` column paths were built from the reference
extraction script and Tenable.sc's public API reference, not a live schema
introspection against a real instance — same caveat as ``wiz.py``,
``appomni.py``, ``snyk.py``, ``cloudflare.py``, ``dnsimple.py``,
``phriendly_phishing.py``, and ``vanta.py``. Verify field names/nesting
against a real instance's response before relying on this collector.
"""

from __future__ import annotations

from typing import Any

from posture.base import Collector
from posture.exceptions import AuthenticationError

_DEFAULT_ASSET_NAME = "Non Crowdstrike Assets"
_DEFAULT_VULN_FILTERS = [
    ("severity", "!=", "0"),  # exclude informational vulnerabilities
    ("lastSeen", "=", "0:30"),  # only vulnerabilities seen in the last 30 days
]
_DEFAULT_VULN_TOOL = "vulndetails"

_HOST_FIELDS = (
    "id,uuid,tenableUUID,name,ipAddress,os,firstSeen,lastSeen,"
    "macAddress,source,repID,netBios,netBiosWorkgroup,createdTime,modifiedTime,acr,aes,"
    "repository.id,repository.name,repository.description"
)
_ASSET_FIELDS = (
    "id,uuid,name,description,type,status,createdTime,modifiedTime,"
    "owner,ownerGroup,groups,template,ipCount,repositories,targetGroup,tags,creator"
)
_HOST_PAGE_LIMIT = 1000

MANIFEST: dict[str, dict[str, Any]] = {
    "vulnerabilities": {
        "columns": {
            "plugin_id": ("pluginID", "str"),
            "plugin_name": ("pluginName", "str"),
            "severity": ("severity.name", "str"),
            "severity_id": ("severity.id", "int"),
            "ip": ("ip", "str"),
            "dns_name": ("dnsName", "str"),
            "mac_address": ("macAddress", "str"),
            "port": ("port", "int"),
            "protocol": ("protocol", "str"),
            "uuid": ("uuid", "str"),
            "repository_id": ("repository.id", "str"),
            "repository_name": ("repository.name", "str"),
            "first_seen": ("firstSeen", "datetime"),
            "last_seen": ("lastSeen", "datetime"),
            "cve": ("cve", "json"),
            "cvss_base_score": ("baseScore", "float"),
            "cvss3_base_score": ("cvssV3BaseScore", "float"),
            "solution": ("solution", "str"),
            "synopsis": ("synopsis", "str"),
            "state": ("state", "str"),
        },
    },
    "hosts": {
        "columns": {
            "id": ("id", "str"),
            "uuid": ("uuid", "str"),
            "tenable_uuid": ("tenableUUID", "str"),
            "name": ("name", "str"),
            "ip_address": ("ipAddress", "str"),
            "os": ("os", "str"),
            "first_seen": ("firstSeen", "datetime"),
            "last_seen": ("lastSeen", "datetime"),
            "mac_address": ("macAddress", "str"),
            "source": ("source", "str"),
            "rep_id": ("repID", "str"),
            "net_bios": ("netBios", "str"),
            "net_bios_workgroup": ("netBiosWorkgroup", "str"),
            "created_time": ("createdTime", "datetime"),
            "modified_time": ("modifiedTime", "datetime"),
            "acr": ("acr", "str"),
            "aes": ("aes", "str"),
            "repository_id": ("repository.id", "str"),
            "repository_name": ("repository.name", "str"),
            "repository_description": ("repository.description", "str"),
        },
    },
    "assets": {
        "columns": {
            "id": ("id", "str"),
            "uuid": ("uuid", "str"),
            "name": ("name", "str"),
            "description": ("description", "str"),
            "type": ("type", "str"),
            "status": ("status", "str"),
            "created_time": ("createdTime", "datetime"),
            "modified_time": ("modifiedTime", "datetime"),
            "owner_id": ("owner.id", "str"),
            "owner_name": ("owner.name", "str"),
            "owner_group_id": ("ownerGroup.id", "str"),
            "owner_group_name": ("ownerGroup.name", "str"),
            "ip_count": ("ipCount", "int"),
            "target_group": ("targetGroup", "json"),
            "groups": ("groups", "json"),
            "repositories": ("repositories", "json"),
            "tags": ("tags", "str"),
            "creator_id": ("creator.id", "str"),
            "creator_name": ("creator.name", "str"),
        },
    },
    "asset_ips": {
        "columns": {
            "asset_id": ("asset_id", "str"),
            "asset_name": ("asset_name", "str"),
            "repository_name": ("repository_name", "str"),
            "ip": ("ip", "str"),
        },
    },
}


def _expand_ip_range(ip_range: str) -> list[str]:
    """Expand a Tenable.sc IP range entry into individual IPv4 addresses.

    Handles both full ranges ("10.8.16.26-10.8.16.30") and the
    last-octet-only shorthand Tenable.sc also emits ("10.8.16.26-27").
    """
    if "-" not in ip_range:
        return [ip_range]

    start, end = ip_range.split("-")
    if "." not in end:
        end = ".".join(start.split(".")[:-1] + [end])

    start_octets = [int(part) for part in start.split(".")]
    end_octets = [int(part) for part in end.split(".")]
    start_int = sum(octet << (8 * (3 - i)) for i, octet in enumerate(start_octets))
    end_int = sum(octet << (8 * (3 - i)) for i, octet in enumerate(end_octets))

    return [
        ".".join(str((ip >> (8 * (3 - i))) & 0xFF) for i in range(4))
        for ip in range(start_int, end_int + 1)
    ]


class TenablescCollector(Collector):
    env_prefix = "TENABLESC"
    display_name = "Tenable.sc"
    manifest = MANIFEST
    required_config_keys = ("endpoint", "access_key", "secret_key")

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        self._asset_id_cache: dict[str, str] = {}

    def _authenticate(self) -> None:
        try:
            from tenable.sc import TenableSC
        except ImportError as exc:
            raise ImportError(
                "pytenable is required for the Tenable.sc collector. "
                'Install it with: pip install "posture[tenablesc]"'
            ) from exc

        try:
            self._sc = TenableSC(
                url=self._config["endpoint"],
                access_key=self._config["access_key"],
                secret_key=self._config["secret_key"],
                retries=5,
                backoff=1,
            )
        except Exception as exc:  # noqa: BLE001 - pytenable raises its own taxonomy
            raise AuthenticationError(
                "Tenable.sc rejected the provided API keys",
                source="tenablesc",
                hint="check TENABLESC_ACCESS_KEY / TENABLESC_SECRET_KEY",
            ) from exc

    def _resolve_asset_id(self, asset_name: str) -> str:
        cached = self._asset_id_cache.get(asset_name)
        if cached is not None:
            return cached

        response = self._sc.get(
            "asset",
            params={"filter": "usable,excludeAllDefined", "fields": "id,name"},
        )
        data = response.json().get("response", {})
        for category in ("usable", "manageable"):
            for asset in data.get(category, []):
                if asset.get("name") == asset_name:
                    asset_id = asset["id"]
                    self._asset_id_cache[asset_name] = asset_id
                    return asset_id

        raise ValueError(f"Could not find Tenable.sc asset list named '{asset_name}'")

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "vulnerabilities":
            return self._fetch_vulnerabilities(kwargs, cursor)
        if resource == "assets":
            return self._fetch_assets(cursor)
        if resource == "hosts":
            return self._fetch_hosts(kwargs, cursor)
        if resource == "asset_ips":
            return self._fetch_asset_ips(kwargs, cursor)
        raise ValueError(f"Unsupported resource '{resource}'")

    def _fetch_vulnerabilities(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None

        filters = kwargs.get("filters", _DEFAULT_VULN_FILTERS)
        tool = kwargs.get("tool", _DEFAULT_VULN_TOOL)
        records = list(self._sc.analysis.vulns(filters=filters, tool=tool))
        return records, None

    def _fetch_assets(self, cursor: Any) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None

        response = self._sc.get(
            "asset",
            params={"filter": "usable,excludeAllDefined", "fields": _ASSET_FIELDS},
        )
        data = response.json().get("response", {})
        seen_ids: set[str] = set()
        records: list[dict[str, Any]] = []
        for category in ("usable", "manageable"):
            for asset in data.get(category, []):
                asset_id = asset.get("id")
                if asset_id in seen_ids:
                    continue
                seen_ids.add(asset_id)
                records.append(asset)
        return records, None

    def _fetch_hosts(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        asset_name = kwargs.get("asset_name", _DEFAULT_ASSET_NAME)
        asset_id = self._resolve_asset_id(asset_name)

        offset = cursor or 0
        response = self._sc.get(
            "hosts",
            params={
                "startOffset": offset,
                "endOffset": offset + _HOST_PAGE_LIMIT,
                "filter": f"asset={asset_id}",
                "fields": _HOST_FIELDS,
            },
        )
        records = response.json().get("response", [])
        next_cursor = (
            offset + _HOST_PAGE_LIMIT if len(records) == _HOST_PAGE_LIMIT else None
        )
        return records, next_cursor

    def _fetch_asset_ips(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None

        asset_name = kwargs.get("asset_name", _DEFAULT_ASSET_NAME)
        asset_id = self._resolve_asset_id(asset_name)

        response = self._sc.get(f"asset/{asset_id}", params={"fields": "viewableIPs"})
        data = response.json().get("response", {})

        records: list[dict[str, Any]] = []
        for repo in data.get("viewableIPs", []):
            ip_list = repo.get("ipList") or ""
            repository_name = repo.get("repository", {}).get("name")
            for raw_entry in (
                entry.strip() for entry in ip_list.strip().split("\n") if entry.strip()
            ):
                for ip in _expand_ip_range(raw_entry):
                    records.append(
                        {
                            "asset_id": asset_id,
                            "asset_name": asset_name,
                            "repository_name": repository_name,
                            "ip": ip,
                        }
                    )
        return records, None
