"""Shared Google Workspace service-account (domain-wide delegation) OAuth2
helpers.

Internal to the Google-family collectors (today just ``google_workspace``).
Google's Admin SDK needs a fundamentally different auth mechanic to Azure's
plain client-credentials POST (see ``_azure_oauth.py``): a service-account
JWT-bearer flow, where the JWT's ``sub`` claim impersonates a real super
admin (domain-wide delegation) and the whole assertion must be RSA-signed
with the service account's private key before it's exchanged for a token.

``cryptography`` is required for the RS256 signing step — Python's stdlib
has no RSA-signing primitive. It's an optional dependency (``pip install
"posture[google_workspace]"``), lazily imported here rather than at module
level, matching how ``tenableio.py``/``tenablesc.py``/``salesforce.py``
guard their vendor SDK imports. Deliberately *not* using Google's own
``google-auth`` library: that pulls in its own credential-caching/retry/ADC
machinery, which would duplicate (and fight) ``base.py``'s existing auth
lifecycle and retry logic. Everything past the token exchange stays plain
``requests``, same as every other collector here.
"""

from __future__ import annotations

import base64
import json
import logging
import time
from pathlib import Path
from typing import Any, NamedTuple

import requests

from posture.base import RateLimitedSignal, UnauthorizedSignal
from posture.exceptions import AuthenticationError

logger = logging.getLogger("posture.collectors.google_oauth")

_DEFAULT_TOKEN_URI = "https://oauth2.googleapis.com/token"
_JWT_LIFETIME_SECONDS = 3600

# Google signals both genuine rate limiting and a permission/scope denial as
# HTTP 403 — the body's error reason is the only way to tell them apart.
_RATE_LIMIT_REASONS = {"rateLimitExceeded", "userRateLimitExceeded", "quotaExceeded"}


class GoogleWorkspaceToken(NamedTuple):
    access_token: str
    expires_in: int


class GoogleWorkspaceError(Exception):
    """A Google API call failed for a reason retrying won't fix (e.g. a
    scope the domain admin never authorized for this service account) —
    raised instead of UnauthorizedSignal so base.py doesn't burn retries
    re-authenticating against an unchanged, permanently-denied scope."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"Google API error: {reason}")
        self.reason = reason


def _b64url(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def _sign_and_exchange(
    session: requests.Session,
    *,
    service_account_json_path: str,
    scopes: list[str],
    source: str,
    subject: str | None,
    hint: str,
) -> GoogleWorkspaceToken:
    """Build an RS256-signed JWT assertion for the service account and
    exchange it for an access token.

    ``subject`` set = domain-wide delegation (the assertion impersonates
    that user); ``subject`` None = the service account acts as itself, which
    is what resource-scoped APIs like Security Command Center use.
    """
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError as exc:
        raise ImportError(
            "cryptography is required for Google service-account auth. "
            'Install it with: pip install "posture[google_workspace]" (or '
            '"posture[gcp_security_command_center]")'
        ) from exc

    key_data = json.loads(Path(service_account_json_path).read_text())
    private_key = serialization.load_pem_private_key(
        key_data["private_key"].encode(), password=None
    )
    token_uri = key_data.get("token_uri", _DEFAULT_TOKEN_URI)

    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    claims = {
        "iss": key_data["client_email"],
        "scope": " ".join(scopes),
        "aud": token_uri,
        "iat": now,
        "exp": now + _JWT_LIFETIME_SECONDS,
    }
    if subject is not None:
        claims["sub"] = subject
    signing_input = b".".join(
        _b64url(json.dumps(part, separators=(",", ":")).encode())
        for part in (header, claims)
    )
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    assertion = signing_input + b"." + _b64url(signature)

    response = session.post(
        token_uri,
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion.decode(),
        },
        timeout=30,
    )
    if response.status_code != 200:
        # Google's OAuth token errors (invalid_grant — commonly an
        # un-authorized scope, or an admin_email outside the domain) come
        # back as 400, not 401.
        raise AuthenticationError(
            f"{source} rejected the service account token request: {response.text}",
            source=source.lower(),
            hint=hint,
        )
    body = response.json()
    return GoogleWorkspaceToken(
        access_token=body["access_token"], expires_in=int(body["expires_in"])
    )


def fetch_google_workspace_token(
    session: requests.Session,
    *,
    service_account_json_path: str,
    admin_email: str,
    scopes: list[str],
    source: str,
) -> GoogleWorkspaceToken:
    return _sign_and_exchange(
        session,
        service_account_json_path=service_account_json_path,
        scopes=scopes,
        source=source,
        subject=admin_email,
        hint=f"check {source.upper()}_SERVICE_ACCOUNT_JSON_PATH / "
        f"{source.upper()}_ADMIN_EMAIL, and that every requested scope "
        "is authorized for this client ID in the Admin console's "
        "domain-wide delegation settings",
    )


def fetch_google_service_account_token(
    session: requests.Session,
    *,
    service_account_json_path: str,
    scopes: list[str],
    source: str,
) -> GoogleWorkspaceToken:
    """Token for the service account acting as itself (no impersonation) —
    for GCP resource APIs (e.g. Security Command Center) where access is
    granted by an IAM role binding on the org/project, not domain-wide
    delegation."""
    return _sign_and_exchange(
        session,
        service_account_json_path=service_account_json_path,
        scopes=scopes,
        source=source,
        subject=None,
        hint=f"check {source.upper()}_SERVICE_ACCOUNT_JSON_PATH and that the "
        "service account has the required Security Command Center IAM role "
        "on the organization",
    )


def google_get_json(
    session: requests.Session, url: str, params: dict[str, Any] | None
) -> dict[str, Any]:
    response = session.get(url, params=params, timeout=60)
    if response.status_code == 429:
        raise RateLimitedSignal()
    if response.status_code == 403:
        reason = _error_reason(response)
        if reason in _RATE_LIMIT_REASONS:
            raise RateLimitedSignal()
        raise GoogleWorkspaceError(reason or "forbidden")
    if response.status_code == 401:
        raise UnauthorizedSignal()
    if response.status_code != 200:
        logger.warning(
            "unexpected status code",
            extra={"source": "google_workspace", "status_code": response.status_code},
        )
    response.raise_for_status()
    return response.json()


def _error_reason(response: requests.Response) -> str | None:
    try:
        errors = response.json().get("error", {}).get("errors", [])
    except ValueError:
        return None
    return errors[0].get("reason") if errors else None
