import json
from datetime import datetime, timezone

import pytest
import responses

from posture import CCM
from posture.exceptions import AuthenticationError, IncompleteCollection

BASE = "https://pvwa.example.com/PasswordVault/"
IDENTITY = "https://abc1234.id.cyberark.cloud"
SELF_HOSTED = {
    "base_url": "pvwa.example.com",
    "username": "ccm",
    "password": "secret",
}
PRIVILEGE_CLOUD = {**SELF_HOSTED, "identity_url": "abc1234.id.cyberark.cloud"}

ACCOUNT = {
    "id": "12_3",
    "name": "Operating System-WinDomain-corp-svc_sql",
    "address": "corp.example.com",
    "userName": "svc_sql",
    "platformId": "WinDomain",
    "safeName": "Finance",
    "secretType": "password",
    "secretManagement": {
        "automaticManagementEnabled": True,
        "status": "success",
        "lastModifiedTime": 1760000000,
    },
    "createdTime": 1750000000,
}


def _logon() -> None:
    responses.add(responses.POST, BASE + "API/auth/CyberArk/Logon", json="sess-tok")


@responses.activate
def test_self_hosted_logon_and_next_link_pagination() -> None:
    _logon()
    responses.add(
        responses.GET,
        BASE + "API/Accounts",
        json={
            "value": [ACCOUNT],
            "count": 2,
            "nextLink": "api/Accounts?offset=1&limit=1000",
        },
    )
    responses.add(
        responses.GET,
        BASE + "api/Accounts",
        json={"value": [{"id": "12_4", "safeName": "Finance"}], "count": 2},
    )

    df = CCM("cyberark", SELF_HOSTED).collect("accounts")

    assert list(df["id"]) == ["12_3", "12_4"]
    assert bool(df.loc[0, "automatic_management_enabled"]) is True
    assert df.loc[0, "management_status"] == "success"
    assert df.loc[0, "last_modified"].year == 2025

    logon, first, second = responses.calls
    assert json.loads(logon.request.body)["concurrentSession"] is True
    assert first.request.headers["Authorization"] == "sess-tok"
    assert first.request.params == {"limit": "1000"}
    assert second.request.params == {"offset": "1", "limit": "1000"}


@responses.activate
def test_privilege_cloud_platform_token() -> None:
    responses.add(
        responses.POST,
        IDENTITY + "/oauth2/platformtoken",
        json={"access_token": "jwt", "expires_in": 900},
    )
    responses.add(
        responses.GET,
        BASE + "API/Safes",
        json={"value": [{"safeUrlId": "Finance", "safeName": "Finance"}]},
    )

    ccm = CCM("cyberark", PRIVILEGE_CLOUD)
    df = ccm.collect("safes", search="Fin")

    assert list(df["safe_name"]) == ["Finance"]
    token, safes = responses.calls
    assert "grant_type=client_credentials" in token.request.body
    assert safes.request.headers["Authorization"] == "Bearer jwt"
    assert safes.request.params == {"limit": "1000", "search": "Fin"}
    remaining = ccm._token_expires_at - datetime.now(timezone.utc)
    assert 800 < remaining.total_seconds() <= 900


@responses.activate
def test_safe_members_fan_out_per_safe() -> None:
    _logon()
    responses.add(
        responses.GET,
        BASE + "API/Safes",
        json={
            "value": [
                {"safeUrlId": "Finance", "safeName": "Finance"},
                {"safeUrlId": "HR Team", "safeName": "HR Team"},
            ]
        },
    )
    responses.add(
        responses.GET,
        BASE + "API/Safes/Finance/Members",
        json={
            "value": [
                {
                    "safeUrlId": "Finance",
                    "memberName": "alice",
                    "memberType": "User",
                    "permissions": {"useAccounts": True, "retrieveAccounts": False},
                }
            ]
        },
    )
    responses.add(
        responses.GET,
        BASE + "API/Safes/HR%20Team/Members",
        json={"value": [{"safeUrlId": "HR Team", "memberName": "hr-admins"}]},
    )

    df = CCM("cyberark", SELF_HOSTED).collect("safe_members")

    assert sorted(df["member_name"]) == ["alice", "hr-admins"]
    alice = df[df["member_name"] == "alice"].iloc[0]
    assert bool(alice["use_accounts"]) is True
    assert bool(alice["retrieve_accounts"]) is False


@responses.activate
def test_bad_credentials_raise_authentication_error() -> None:
    responses.add(responses.POST, BASE + "API/auth/CyberArk/Logon", status=401)
    ccm = CCM("cyberark", SELF_HOSTED)

    with pytest.raises(AuthenticationError):
        ccm.collect("accounts")


@responses.activate
def test_insecure_applies_to_logon_and_api_calls() -> None:
    _logon()
    responses.add(responses.GET, BASE + "API/Safes", json={"value": []})

    CCM("cyberark", {**SELF_HOSTED, "insecure": "true"}).collect("safes")

    assert all(call.request.req_kwargs["verify"] is False for call in responses.calls)


@responses.activate
def test_ldap_logon_type_selects_logon_path() -> None:
    responses.add(responses.POST, BASE + "API/auth/LDAP/Logon", json="sess-tok")
    responses.add(responses.GET, BASE + "API/Safes", json={"value": []})

    CCM("cyberark", {**SELF_HOSTED, "logon_type": "ldap"}).collect("safes")

    assert responses.calls[0].request.url == BASE + "API/auth/LDAP/Logon"


def test_invalid_logon_type_raises() -> None:
    with pytest.raises(ValueError, match="logon_type"):
        CCM("cyberark", {**SELF_HOSTED, "logon_type": "saml"})


@responses.activate
def test_safe_members_rejects_kwargs() -> None:
    _logon()
    ccm = CCM("cyberark", SELF_HOSTED)

    with pytest.raises(IncompleteCollection, match="Unsupported kwargs"):
        ccm.collect("safe_members", search="x")
