"""Cisco Duo collector.

Raw ``requests`` against the Duo Admin API
(``https://api-XXXXXXXX.duosecurity.com/admin/v1/...``) — no vendor SDK.
The API hostname is per-customer (issued when the Admin API application is
created in the Duo Admin Panel), so ``api_hostname`` is required config, the
same "operator supplies the host, no cross-tenant discovery" shape as
``wiz.py``'s ``api_endpoint`` / ``sentinelone.py``'s ``console_url``.

Auth is not a token exchange: every request is individually signed with an
HMAC-SHA1 of a canonical request string (date, method, host, path, sorted
query params) keyed by the integration's secret key, sent as HTTP Basic
auth (``integration_key`` as the username, the hex signature as the
password). ``_authenticate`` therefore only validates the credentials with
one cheap signed call — there is no bearer header to cache — and every
``_fetch_page`` re-signs.

Pagination is a single ``offset``/``limit`` scheme shared by every list
endpoint, with the envelope ``{"stat": "OK", "response": [...],
"metadata": {"next_offset": N}}`` — ``next_offset`` absent means the last
page. Duo's timestamps are Unix epoch seconds, parsed by ``parse.py``'s
epoch-by-magnitude cascade with no ``format`` hint needed.

Resources: ``users``, ``groups``, ``phones``, ``endpoints``, ``admins``,
``integrations``.

**Caveat:** ``MANIFEST`` column paths below were built from Duo's public
Admin API reference, not a live schema introspection against a real tenant
— same caveat as ``wiz.py``, ``appomni.py``, ``snyk.py``, and
``cloudflare.py``. Verify field names/nesting against a real tenant's
response before relying on this collector.
"""

from __future__ import annotations

import base64
import email.utils
import hashlib
import hmac
import logging
import urllib.parse
from typing import Any, ClassVar

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal
from posture.exceptions import AuthenticationError

logger = logging.getLogger("posture.collectors.duo")

_PAGE_SIZE = 100

_USERS_PATH = "/admin/v1/users"
_GROUPS_PATH = "/admin/v1/groups"
_PHONES_PATH = "/admin/v1/phones"
_ENDPOINTS_PATH = "/admin/v1/endpoints"
_ADMINS_PATH = "/admin/v1/admins"
_INTEGRATIONS_PATH = "/admin/v1/integrations"

MANIFEST: dict[str, dict[str, Any]] = {
    "users": {
        "endpoint": _USERS_PATH,
        "columns": {
            "user_id": ("user_id", "str"),
            "username": ("username", "str"),
            "realname": ("realname", "str"),
            "email": ("email", "str"),
            "status": ("status", "str"),
            "first_name": ("firstname", "str"),
            "last_name": ("lastname", "str"),
            "is_enrolled": ("is_enrolled", "bool"),
            "created": ("created", "datetime"),
            "last_login": ("last_login", "datetime"),
            "last_directory_sync": ("last_directory_sync", "datetime"),
            "notes": ("notes", "str"),
            "aliases": ("aliases", "json"),
            "groups": ("groups", "json"),
            "phones": ("phones", "json"),
            "tokens": ("tokens", "json"),
            "webauthncredentials": ("webauthncredentials", "json"),
        },
    },
    "groups": {
        "endpoint": _GROUPS_PATH,
        "columns": {
            "group_id": ("group_id", "str"),
            "name": ("name", "str"),
            "description": ("desc", "str"),
            "status": ("status", "str"),
            "push_enabled": ("push_enabled", "bool"),
            "sms_enabled": ("sms_enabled", "bool"),
            "voice_enabled": ("voice_enabled", "bool"),
            "mobile_otp_enabled": ("mobile_otp_enabled", "bool"),
        },
    },
    "phones": {
        "endpoint": _PHONES_PATH,
        "columns": {
            "phone_id": ("phone_id", "str"),
            "number": ("number", "str"),
            "extension": ("extension", "str"),
            "name": ("name", "str"),
            "type": ("type", "str"),
            "platform": ("platform", "str"),
            "model": ("model", "str"),
            "activated": ("activated", "bool"),
            "sms_passcodes_sent": ("sms_passcodes_sent", "bool"),
            "last_seen": ("last_seen", "datetime"),
            "capabilities": ("capabilities", "json"),
            "users": ("users", "json"),
        },
    },
    "endpoints": {
        "endpoint": _ENDPOINTS_PATH,
        "columns": {
            "epkey": ("epkey", "str"),
            "username": ("username", "str"),
            "email": ("email", "str"),
            "computer_name": ("computer_name", "str"),
            "model": ("model", "str"),
            "type": ("type", "str"),
            "os_family": ("os_family", "str"),
            "os_version": ("os_version", "str"),
            "os_build": ("os_build", "str"),
            "device_identifier": ("device_identifier", "str"),
            "device_udid": ("device_udid", "str"),
            "hardware_uuid": ("hardware_uuid", "str"),
            "disk_encryption_status": ("disk_encryption_status", "str"),
            "firewall_status": ("firewall_status", "str"),
            "password_status": ("password_status", "str"),
            "trusted_endpoint": ("trusted_endpoint", "str"),
            "health_app_client_version": ("health_app_client_version", "str"),
            "security_agents": ("security_agents", "json"),
            "browsers": ("browsers", "json"),
            "last_updated": ("last_updated", "datetime"),
        },
    },
    "admins": {
        "endpoint": _ADMINS_PATH,
        "columns": {
            "admin_id": ("admin_id", "str"),
            "name": ("name", "str"),
            "email": ("email", "str"),
            "phone": ("phone", "str"),
            "role": ("role", "str"),
            "status": ("status", "str"),
            "restricted_by_admin_units": ("restricted_by_admin_units", "bool"),
            "password_change_required": ("password_change_required", "bool"),
            "last_login": ("last_login", "datetime"),
            "created": ("created", "datetime"),
            "admin_units": ("admin_units", "json"),
        },
    },
    "integrations": {
        "endpoint": _INTEGRATIONS_PATH,
        "columns": {
            "integration_key": ("integration_key", "str"),
            "name": ("name", "str"),
            "type": ("type", "str"),
            "enroll_policy": ("enroll_policy", "str"),
            "greeting": ("greeting", "str"),
            "notes": ("notes", "str"),
            "trusted_device_days": ("trusted_device_days", "int"),
            "self_service_allowed": ("self_service_allowed", "bool"),
            "username_normalization_policy": (
                "username_normalization_policy",
                "str",
            ),
            "networks_for_api_access": ("networks_for_api_access", "json"),
            "adminapi_admins": ("adminapi_admins", "bool"),
            "adminapi_read_resource": ("adminapi_read_resource", "bool"),
            "adminapi_write_resource": ("adminapi_write_resource", "bool"),
            "adminapi_read_log": ("adminapi_read_log", "bool"),
            "adminapi_settings": ("adminapi_settings", "bool"),
        },
    },
}


class DuoCollector(Collector):
    env_prefix = "DUO"
    display_name = "Cisco Duo"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {
        "api_hostname": True,
        "integration_key": True,
        "secret_key": True,
    }
    url_config_keys = ("api_hostname",)

    def _authenticate(self) -> None:
        # No bearer token: every request is signed independently. This call
        # only proves the credentials/host are usable, failing fast on a
        # misconfigured application rather than on the first real fetch.
        status, _ = self._signed_get(_USERS_PATH, {"limit": "1", "offset": "0"})
        if status in (401, 403):
            raise AuthenticationError(
                "Duo rejected the Admin API credentials",
                source="duo",
                hint="check DUO_API_HOSTNAME / DUO_INTEGRATION_KEY / DUO_SECRET_KEY "
                "and that the application has 'Grant read resource' permission",
            )

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        manifest = MANIFEST.get(resource)
        if manifest is None:
            raise ValueError(f"Unsupported resource '{resource}'")

        offset = int(cursor) if cursor is not None else 0
        params: dict[str, str] = {"limit": str(_PAGE_SIZE), "offset": str(offset)}
        params.update({k: str(v) for k, v in kwargs.items()})

        status, payload = self._signed_get(manifest["endpoint"], params)
        if status == 429:
            raise RateLimitedSignal()
        if status in (401, 403):
            raise UnauthorizedSignal()
        if status != 200 or payload.get("stat") != "OK":
            detail = payload.get("message") or payload.get("message_detail") or status
            raise RuntimeError(f"Duo API request failed: {detail}")

        records = payload.get("response", []) or []
        next_offset = (payload.get("metadata") or {}).get("next_offset")
        return records, next_offset

    def _signed_get(
        self, path: str, params: dict[str, str]
    ) -> tuple[int, dict[str, Any]]:
        host = self._config["api_hostname"].removeprefix("https://")
        # The exact query string that is signed must be the exact query
        # string that is sent — build it once, sign it, and pass it through
        # verbatim rather than letting requests re-encode a params dict.
        canon_params = "&".join(
            f"{urllib.parse.quote(k, safe='~')}={urllib.parse.quote(v, safe='~')}"
            for k, v in sorted(params.items())
        )
        date = email.utils.formatdate()
        canon = f"{date}\nGET\n{host.lower()}\n{path}\n{canon_params}"
        signature = hmac.new(
            self._config["secret_key"].encode(),
            canon.encode(),
            hashlib.sha1,
        ).hexdigest()
        basic = base64.b64encode(
            f"{self._config['integration_key']}:{signature}".encode()
        ).decode()

        url = f"https://{host}{path}"
        if canon_params:
            url = f"{url}?{canon_params}"
        response = self._session.get(
            url,
            headers={"Date": date, "Authorization": f"Basic {basic}"},
            timeout=30,
        )
        if response.status_code == 429:
            return 429, {}
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        return response.status_code, payload
