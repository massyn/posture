from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from posture import CCM

FIXTURES = Path(__file__).parent / "fixtures" / "servicenow"

_OAUTH_CONFIG = {
    "instance": "acme",
    "client_id": "cid",
    "client_secret": "secret",
    "username": "svc_posture",
    "password": "pw",
}

_BASIC_CONFIG = {
    "instance": "acme",
    "auth_type": "basic",
    "username": "svc_posture",
    "password": "pw",
}


def _mock_response(status_code=200, json_data=None):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = json_data or {}
    response.raise_for_status = MagicMock()
    return response


def test_oauth2_authenticates_then_fetches_page() -> None:
    ccm = CCM("servicenow", _OAUTH_CONFIG)

    token_response = _mock_response(json_data={"access_token": "tok123"})
    page_response = _mock_response(
        json_data={"result": [{"sys_id": "1", "name": "srv01"}]}
    )

    with (
        patch.object(ccm._session, "post", return_value=token_response) as fake_post,
        patch.object(ccm._session, "get", return_value=page_response) as fake_get,
    ):
        df = ccm.collect("cmdb_ci")

    fake_post.assert_called_once_with(
        "https://acme.service-now.com/oauth_token.do",
        data={
            "grant_type": "password",
            "client_id": "cid",
            "client_secret": "secret",
            "username": "svc_posture",
            "password": "pw",
        },
        timeout=30,
    )
    assert ccm._session.headers["Authorization"] == "Bearer tok123"
    called_url = fake_get.call_args[0][0]
    assert called_url == "https://acme.service-now.com/api/now/table/cmdb_ci"
    assert len(df) == 1
    assert df.loc[0, "sys_id"] == "1"


def test_basic_auth_sets_session_auth_without_token_request() -> None:
    ccm = CCM("servicenow", _BASIC_CONFIG)

    page_response = _mock_response(json_data={"result": []})

    with (
        patch.object(ccm._session, "post") as fake_post,
        patch.object(ccm._session, "get", return_value=page_response),
    ):
        ccm.collect("cmdb_ci")

    fake_post.assert_not_called()
    assert ccm._session.auth == ("svc_posture", "pw")


def test_pagination_stops_when_page_smaller_than_limit() -> None:
    ccm = CCM("servicenow", _OAUTH_CONFIG)

    token_response = _mock_response(json_data={"access_token": "tok123"})
    page_response = _mock_response(json_data={"result": [{"sys_id": "1"}]})

    with (
        patch.object(ccm._session, "post", return_value=token_response),
        patch.object(ccm._session, "get", return_value=page_response) as fake_get,
    ):
        df = ccm.collect("cmdb_ci")

    assert fake_get.call_count == 1
    assert len(df) == 1
    assert ccm.report("cmdb_ci")["pages"] == 1


def test_missing_oauth_credentials_raises() -> None:
    with pytest.raises(ValueError, match="client_id"):
        CCM("servicenow", {"instance": "acme"})


def test_invalid_auth_type_raises() -> None:
    with pytest.raises(ValueError, match="Invalid SERVICENOW_AUTH_TYPE"):
        CCM("servicenow", {"instance": "acme", "auth_type": "kerberos"})


def test_custom_schema_file_overrides_default_manifest() -> None:
    ccm = CCM(
        "servicenow",
        {**_OAUTH_CONFIG, "schema_file": str(FIXTURES / "custom_schema.json")},
    )

    assert "widget" in ccm.manifest
    assert "cmdb_ci" not in ccm.manifest


def test_tables_lists_manifest_resources() -> None:
    ccm = CCM("servicenow", _OAUTH_CONFIG)
    assert set(ccm.tables()) == set(ccm.manifest)
