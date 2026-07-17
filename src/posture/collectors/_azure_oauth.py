"""Shared Azure AD OAuth2 helpers.

Internal to the Microsoft-family collectors (``intune``, ``mde``) — both
authenticate against Azure AD client-credentials with the same token
exchange, just a different scope. Not part of the public Collector contract;
promoted out of a single collector into this shared module only because a
second collector (MDE) demonstrably needed the same logic, per the
anti-overfitting rule in CLAUDE.md.

``odata_get_page`` (the ``value``/``@odata.nextLink`` pager) is only valid
for Microsoft Graph, which Intune uses — MDE's API never returns
``@odata.nextLink`` on any endpoint (confirmed against Microsoft's own docs),
so ``mde.py`` implements its own ``$top``/``$skip`` pagination instead of
using it.
"""

from __future__ import annotations

from typing import Any

import requests

from posture.base import RateLimitedSignal, UnauthorizedSignal
from posture.exceptions import AuthenticationError


def fetch_azure_ad_token(
    session: requests.Session,
    *,
    tenant_id: str,
    client_id: str,
    client_secret: str,
    scope: str,
    source: str,
) -> str:
    response = session.post(
        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        data={
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope,
            "grant_type": "client_credentials",
        },
        timeout=30,
    )
    if response.status_code == 401:
        raise AuthenticationError(
            f"{source} rejected client credentials",
            source=source.lower(),
            hint=f"check {source.upper()}_CLIENT_ID / {source.upper()}_CLIENT_SECRET / "
            f"{source.upper()}_TENANT_ID",
        )
    response.raise_for_status()
    return response.json()["access_token"]


def odata_get_page(
    session: requests.Session, url: str, params: dict[str, Any] | None
) -> tuple[list[dict[str, Any]], str | None]:
    """Fetch one OData page. If ``params`` is None, ``url`` is an opaque
    ``@odata.nextLink`` and is fetched as-is."""
    response = session.get(url, params=params, timeout=60)
    if response.status_code == 429:
        retry_after = response.headers.get("Retry-After")
        raise RateLimitedSignal(retry_after=float(retry_after) if retry_after else None)
    if response.status_code in (401, 403):
        raise UnauthorizedSignal()
    response.raise_for_status()

    body = response.json()
    records = body.get("value", [])
    next_link = body.get("@odata.nextLink")
    return records, next_link
