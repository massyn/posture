"""Authentication for the Qualys gateway host, shared by every gateway-hosted
table family (CSAM in ``assets.py``, Container Security in ``containers.py``).

The gateway (``https://gateway.qgN.apps.qualys.com``) is a different host from
the ``qualysapi`` server the ``/fo/`` and WAS tables use, and authenticates
with a JWT rather than Basic auth.

Gateway URL: ``gateway_url`` when configured, otherwise derived from
``base_url`` by ``gateway_url_for`` (every public platform's gateway follows
its API server's host). A ``base_url`` that doesn't follow the pattern (a
private cloud platform) fails only the gateway tables, asking for
``QUALYS_GATEWAY_URL``.

Auth: ``POST {gateway_url}/auth`` with the username/password form fields and
``token=true`` returns the JWT as the plain-text body, sent as
``Authorization: Bearer <jwt>``. One token serves every gateway family, so
collecting both CSAM and Container Security logs in once. It is fetched
lazily on the first gateway request, so a subscription using none of these
modules never logs in to the gateway. Tokens last four hours and are
refreshed ahead of expiry here rather than by the base class (whose
``_token_expires_at`` would re-authenticate every family). A 401 from
``/auth`` itself is ``CredentialsRejected`` (the username or password is
wrong for every Qualys table); a 400 or 403 there fails only the gateway
tables.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import requests

from posture.base import RateLimitedSignal, UnauthorizedSignal
from posture.collectors.qualys.errors import CredentialsRejected
from posture.exceptions import AuthenticationError

_AUTH_PATH = "/auth"
_TOKEN_LIFETIME = timedelta(hours=4)
# Refresh this long before expiry, so a request in flight doesn't race the
# token dying mid-call.
_TOKEN_REFRESH_MARGIN = timedelta(minutes=5)

# The two oldest platforms' API servers predate the qgN naming; their
# gateways don't.
_LEGACY_GATEWAYS = {
    "qualysapi.qualys.com": "gateway.qg1.apps.qualys.com",
    "qualysapi.qualys.eu": "gateway.qg1.apps.qualys.eu",
}


def gateway_url_for(base_url: str) -> str | None:
    """The gateway URL matching an API server URL, or None when ``base_url``
    doesn't follow Qualys's public platform naming."""
    host = urlparse(base_url).hostname or ""
    gateway = _LEGACY_GATEWAYS.get(host)
    if gateway is None and host.startswith("qualysapi."):
        gateway = "gateway." + host.removeprefix("qualysapi.")
    return f"https://{gateway}" if gateway else None


class GatewayAuth:
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
        self.token_issued_at: datetime | None = None
        self.token_expires_at: datetime | None = None

    @property
    def url(self) -> str:
        if self._gateway_url is None:
            raise ValueError(
                "Qualys gateway URL could not be derived from QUALYS_BASE_URL; "
                "set QUALYS_GATEWAY_URL to the subscription's gateway host"
            )
        return self._gateway_url

    def headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._bearer_token()}",
            "Accept": "application/json",
        }

    def check(self, response: requests.Response, resource: str) -> None:
        """Raise for a failed gateway data call, naming the host and keeping
        Qualys's own response text.

        A 401 normally means the token expired, so it is dropped and
        ``UnauthorizedSignal`` makes the base class retry with a fresh one.
        A 401 against a token issued moments ago cannot be expiry: the user
        or subscription lacks that module's API, so it fails the table with
        an ``AuthenticationError`` instead of an empty retry loop. Not
        ``CredentialsRejected``: the login itself worked, so the other
        tables can still collect.
        """
        if response.status_code == 429:
            wait = response.headers.get(
                "X-RateLimit-ToWait-Sec"
            ) or response.headers.get("Retry-After")
            raise RateLimitedSignal(retry_after=float(wait) if wait else None)
        detail = response.text[:300].strip() or "no message"
        if response.status_code == 401:
            if self._issued_recently():
                raise AuthenticationError(
                    f"Qualys gateway {self._host()} refused '{resource}' (HTTP "
                    f"401) with a token it had just issued: {detail}",
                    source="qualys",
                    hint="the login works but this module's API is not "
                    "available to the user: check the subscription includes "
                    "the module (Container Security, CSAM/Global AssetView) "
                    "and the user's role grants its API access and list "
                    "permissions (Qualys Community Edition has no API)",
                )
            self._token = None
            raise UnauthorizedSignal()
        if not response.ok:
            raise requests.HTTPError(
                f"Qualys gateway {self._host()} returned HTTP "
                f"{response.status_code} for '{resource}': {detail}",
                response=response,
            )

    def _issued_recently(self) -> bool:
        # A token this young cannot have expired (it lasts four hours).
        return (
            self.token_issued_at is not None
            and datetime.now(timezone.utc) - self.token_issued_at
            < _TOKEN_REFRESH_MARGIN
        )

    def _host(self) -> str:
        return urlparse(self.url).hostname or self.url

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
            self.url + _AUTH_PATH,
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
                f"Qualys gateway {self._host()} authentication failed "
                f"(HTTP {response.status_code})",
                source="qualys",
                hint="check QUALYS_USERNAME/QUALYS_PASSWORD, that the user has "
                "API access to the module (CSAM/Global AssetView, Container "
                "Security), and that the gateway URL (QUALYS_GATEWAY_URL, or "
                "derived from QUALYS_BASE_URL) is the subscription's gateway host",
            )
        response.raise_for_status()
        self._token = response.text.strip()
        self.token_issued_at = datetime.now(timezone.utc)
        self.token_expires_at = self.token_issued_at + _TOKEN_LIFETIME
        return self._token
