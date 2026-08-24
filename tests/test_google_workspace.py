import json

import pytest
import responses
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from posture import CCM

_TOKEN_URL = "https://oauth2.googleapis.com/token"


@pytest.fixture
def service_account_json_path(tmp_path) -> str:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    path = tmp_path / "service-account.json"
    path.write_text(
        json.dumps(
            {
                "client_email": "ccm@project.iam.gserviceaccount.com",
                "private_key": pem,
                "token_uri": _TOKEN_URL,
            }
        )
    )
    return str(path)


def _mock_token() -> None:
    responses.add(
        responses.POST,
        _TOKEN_URL,
        json={"access_token": "tok", "expires_in": 3600},
        status=200,
    )


def _ccm(service_account_json_path: str) -> CCM:
    return CCM(
        "google_workspace",
        {
            "service_account_json_path": service_account_json_path,
            "admin_email": "admin@example.com",
        },
    )


@responses.activate
def test_users_pagination_follows_next_page_token(service_account_json_path) -> None:
    _mock_token()
    responses.add(
        responses.GET,
        "https://admin.googleapis.com/admin/directory/v1/users",
        json={
            "users": [{"id": "u1", "primaryEmail": "a@example.com"}],
            "nextPageToken": "abc",
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "https://admin.googleapis.com/admin/directory/v1/users",
        json={"users": [{"id": "u2", "primaryEmail": "b@example.com"}]},
        status=200,
    )

    df = _ccm(service_account_json_path).collect("users")

    assert list(df["user_id"]) == ["u1", "u2"]
    # The token exchange posts an RS256-signed JWT-bearer assertion.
    token_request = responses.calls[0].request
    assert "jwt-bearer" in token_request.body
    users_request = responses.calls[1].request
    assert "customer=my_customer" in users_request.url


@responses.activate
def test_group_members_fans_out_per_group(service_account_json_path) -> None:
    _mock_token()
    responses.add(
        responses.GET,
        "https://admin.googleapis.com/admin/directory/v1/groups",
        json={
            "groups": [{"id": "g1"}, {"id": "g2"}],
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "https://admin.googleapis.com/admin/directory/v1/groups/g1/members",
        json={"members": [{"id": "m1", "email": "a@example.com", "role": "OWNER"}]},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://admin.googleapis.com/admin/directory/v1/groups/g2/members",
        json={"members": []},
        status=200,
    )

    df = _ccm(service_account_json_path).collect("group_members")

    assert len(df) == 1
    assert df.loc[0, "group_id"] == "g1"
    assert df.loc[0, "role"] == "OWNER"


@responses.activate
def test_org_units_uses_organization_units_key(service_account_json_path) -> None:
    _mock_token()
    responses.add(
        responses.GET,
        "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/orgunits",
        json={
            "organizationUnits": [{"orgUnitId": "ou1", "orgUnitPath": "/Engineering"}]
        },
        status=200,
    )

    df = _ccm(service_account_json_path).collect("org_units")

    assert df.loc[0, "org_unit_id"] == "ou1"
    assert df.loc[0, "org_unit_path"] == "/Engineering"


@responses.activate
def test_roles_uses_items_key(service_account_json_path) -> None:
    _mock_token()
    responses.add(
        responses.GET,
        "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/roles",
        json={"items": [{"roleId": "r1", "roleName": "Super Admin"}]},
        status=200,
    )

    df = _ccm(service_account_json_path).collect("roles")

    assert df.loc[0, "role_id"] == "r1"
    assert df.loc[0, "role_name"] == "Super Admin"


@responses.activate
def test_missing_scope_403_fails_without_retry(service_account_json_path) -> None:
    from posture.exceptions import IncompleteCollection

    _mock_token()
    responses.add(
        responses.GET,
        "https://admin.googleapis.com/admin/directory/v1/users",
        json={"error": {"errors": [{"reason": "insufficientPermissions"}]}},
        status=403,
    )

    ccm = _ccm(service_account_json_path)

    try:
        ccm.collect("users")
        assert False, "expected IncompleteCollection"
    except IncompleteCollection:
        pass

    assert len(responses.calls) == 2  # token exchange + one failed attempt


@responses.activate
def test_token_exchange_rejected_raises_authentication_error(
    service_account_json_path,
) -> None:
    from posture.exceptions import AuthenticationError

    responses.add(
        responses.POST,
        _TOKEN_URL,
        json={"error": "invalid_grant"},
        status=400,
    )

    ccm = _ccm(service_account_json_path)

    try:
        ccm.collect("users")
        assert False, "expected AuthenticationError"
    except AuthenticationError:
        pass
