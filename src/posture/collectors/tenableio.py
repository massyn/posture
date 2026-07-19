"""Tenable.io collector.

Uses ``pytenable`` (an approved SDK exception — Tenable's export jobs are
bespoke server-side machinery the base class's generic REST pagination
scaffold can't express) rather than raw ``requests``. Each export
(``tio.exports.assets()`` / ``tio.exports.vulns()``) is a single generator
that internally drives pytenable's own job-polling and pagination, so it is
fetched whole on the first ``_fetch_page`` call and the cursor immediately
closes — the base class's retry/backoff/401 machinery still wraps that call.

Resources: ``assets``, ``vulnerabilities``.

Dependencies
------------
    pip install "posture[tenableio]"
"""

from __future__ import annotations

from typing import Any

from posture.base import Collector
from posture.exceptions import AuthenticationError

MANIFEST: dict[str, dict[str, Any]] = {
    "assets": {
        "columns": {
            "asset_id": ("id", "str"),
            "hostname": ("hostnames.0", "str"),
            "fqdn": ("fqdns.0", "str"),
            "ipv4": ("ipv4s.0", "str"),
            "ipv6": ("ipv6s.0", "str"),
            "mac_address": ("mac_addresses.0", "str"),
            "operating_system": ("operating_systems.0", "str"),
            "network_name": ("network_name", "str"),
            "has_agent": ("has_agent", "bool"),
            "agent_uuid": ("agent_uuid", "str"),
            "first_seen": ("first_seen", "datetime"),
            "last_seen": ("last_seen", "datetime"),
            "sources": ("sources", "json"),
        },
    },
    "vulnerabilities": {
        "columns": {
            "asset_uuid": ("asset.uuid", "str"),
            "asset_hostname": ("asset.hostname", "str"),
            "asset_ipv4": ("asset.ipv4", "str"),
            "asset_os": ("asset.operating_system", "str"),
            "plugin_id": ("plugin.id", "int"),
            "plugin_name": ("plugin.name", "str"),
            "plugin_family": ("plugin.family_name", "str"),
            "severity": ("severity", "str"),
            "severity_id": ("severity_id", "int"),
            "cvss_base_score": ("plugin.cvss_base_score", "float"),
            "cvss3_base_score": ("plugin.cvss3_base_score", "float"),
            "cve": ("plugin.cve", "json"),
            "state": ("state", "str"),
            "port": ("port.port", "int"),
            "protocol": ("port.protocol", "str"),
            "first_found": ("first_found", "datetime"),
            "last_found": ("last_found", "datetime"),
        },
    },
}


class TenableioCollector(Collector):
    env_prefix = "TENABLEIO"
    manifest = MANIFEST
    required_config_keys = ("access_key", "secret_key")

    def _authenticate(self) -> None:
        try:
            from tenable.io import TenableIO
        except ImportError as exc:
            raise ImportError(
                "pytenable is required for the Tenable.io collector. "
                'Install it with: pip install "posture[tenableio]"'
            ) from exc

        try:
            self._tio = TenableIO(
                access_key=self._config["access_key"],
                secret_key=self._config["secret_key"],
                retries=5,
                backoff=1,
            )
        except Exception as exc:  # noqa: BLE001 - pytenable raises its own taxonomy
            raise AuthenticationError(
                "Tenable.io rejected the provided API keys",
                source="tenableio",
                hint="check TENABLEIO_ACCESS_KEY / TENABLEIO_SECRET_KEY",
            ) from exc

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if cursor is not None:
            return [], None

        if resource == "assets":
            records = list(self._tio.exports.assets(**kwargs))
        elif resource == "vulnerabilities":
            records = list(self._tio.exports.vulns(**kwargs))
        else:
            raise ValueError(f"Unsupported resource '{resource}'")

        return records, None
