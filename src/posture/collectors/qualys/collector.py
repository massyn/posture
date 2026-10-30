"""The ``qualys`` source: one subscription, one set of credentials, a table
per Qualys dataset.

Qualys exposes its modules through three API families, each with its own
module here:

- ``fo_api.py``: the ``/api/N.0/fo/`` XML API on the API server, Basic auth,
  shared by ``vm.py`` (VMDR) and ``compliance.py`` (Policy Compliance).
- ``webapps.py``: the WAS v3 JSON search API on the API server, Basic auth
  (TotalAppSec).
- ``assets.py``: the CSAM asset search API on the gateway host, JWT auth
  (Global AssetView / CSAM).

This class only routes each table to the module that fetches it. Every
family authenticates its own requests, and the gateway JWT is only fetched
when an ``assets`` table is collected, so a module the subscription doesn't
licence fails its own tables and nothing else.

The exception is the user itself being refused (``CredentialsRejected``: bad
login, inactive or unregistered account). Every family logs in as the same
user, so after the first such rejection this instance sends no further
requests and fails each later table straight away: retrying elsewhere cannot
succeed, and every rejected attempt counts towards Qualys's failed-login
lockout.
"""

from __future__ import annotations

from typing import Any, ClassVar

from posture.base import Collector
from posture.collectors.qualys import assets, compliance, vm, webapps
from posture.collectors.qualys.errors import CredentialsRejected
from posture.collectors.qualys.fo_api import FoApi


class QualysCollector(Collector):
    env_prefix = "QUALYS"
    display_name = "Qualys"
    manifest: ClassVar[dict[str, dict[str, Any]]] = {
        **vm.MANIFEST,
        **compliance.MANIFEST,
        **webapps.MANIFEST,
        **assets.MANIFEST,
    }
    config_keys: ClassVar[dict[str, bool]] = {
        "username": True,
        "password": True,
        "base_url": True,
        # Only needed when the gateway can't be derived from base_url.
        "gateway_url": False,
    }
    url_config_keys: tuple[str, ...] = ("base_url", "gateway_url")

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        base_url = self._config["base_url"]
        credentials = (self._config["username"], self._config["password"])
        fo = FoApi(self._session, base_url, credentials)
        gateway_url = self._config.get("gateway_url") or assets.gateway_url_for(
            base_url
        )
        apis = (
            vm.VmApi(fo),
            compliance.ComplianceApi(fo, self._get_raw),
            webapps.WebappsApi(self._session, base_url, credentials),
            assets.AssetsApi(self._session, gateway_url, credentials),
        )
        self._routes = {resource: api for api in apis for resource in api.resources}
        self._credentials_rejected: CredentialsRejected | None = None

    def _authenticate(self) -> None:
        # Each API family authenticates its own requests (see the module
        # docstring); this header is mandatory on every /fo/ call and
        # harmless on the others.
        self._session.headers["X-Requested-With"] = "posture"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        api = self._routes.get(resource)
        if api is None:
            raise ValueError(f"Unsupported resource '{resource}'")
        rejected = self._credentials_rejected
        if rejected is not None:
            raise CredentialsRejected(
                f"Not sent: Qualys already rejected these credentials in this "
                f"run, and another attempt would count towards its failed-login "
                f"lockout ({rejected})",
                source="qualys",
                hint=rejected.hint,
            ) from rejected
        try:
            return api.fetch_page(resource, kwargs, cursor)
        except CredentialsRejected as exc:
            self._credentials_rejected = exc
            raise
