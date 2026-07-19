from pathlib import Path
from unittest.mock import MagicMock, patch

from posture import CCM

FIXTURES = Path(__file__).parent / "fixtures" / "salesforce"

_CONFIG = {
    "username": "user@example.com",
    "password": "pw",
    "security_token": "token",
}


def test_domain_query_built_from_manifest_and_run_via_query() -> None:
    fake_sf = MagicMock()
    fake_sf.query.return_value = {
        "totalSize": 1,
        "done": True,
        "records": [{"Id": "001", "Name": "example.com", "Active__c": True}],
    }

    with patch("simple_salesforce.Salesforce", return_value=fake_sf) as fake_ctor:
        ccm = CCM("salesforce", _CONFIG)
        df = ccm.collect("domain__c")

    fake_ctor.assert_called_once_with(
        username="user@example.com",
        password="pw",
        security_token="token",
        domain=None,
    )
    fake_sf.query.assert_called_once_with("select Id,Name,Active__c from domain__c")
    assert len(df) == 1
    assert df.loc[0, "id"] == "001"
    assert df.loc[0, "active__c"] == True  # noqa: E712


def test_pagination_follows_next_records_url() -> None:
    fake_sf = MagicMock()
    fake_sf.query.return_value = {
        "totalSize": 2,
        "done": False,
        "nextRecordsUrl": "/services/data/v60.0/query/01g-2000",
        "records": [{"Id": "001", "Name": "a"}],
    }
    fake_sf.query_more.return_value = {
        "totalSize": 2,
        "done": True,
        "records": [{"Id": "002", "Name": "b"}],
    }

    with patch("simple_salesforce.Salesforce", return_value=fake_sf):
        ccm = CCM("salesforce", _CONFIG)
        df = ccm.collect("krow__location__c")

    fake_sf.query_more.assert_called_once_with(
        "/services/data/v60.0/query/01g-2000", identifier_is_url=True
    )
    assert len(df) == 2
    assert ccm.report("krow__location__c")["pages"] == 2


def test_authentication_error_on_bad_credentials() -> None:
    from posture.exceptions import AuthenticationError

    with patch("simple_salesforce.Salesforce", side_effect=Exception("INVALID_LOGIN")):
        ccm = CCM("salesforce", _CONFIG)
        try:
            ccm.collect("domain__c")
            assert False, "expected AuthenticationError"
        except AuthenticationError:
            pass


def test_domain_config_passed_through_to_sandbox() -> None:
    fake_sf = MagicMock()
    fake_sf.query.return_value = {"totalSize": 0, "done": True, "records": []}

    with patch("simple_salesforce.Salesforce", return_value=fake_sf) as fake_ctor:
        ccm = CCM("salesforce", {**_CONFIG, "domain": "test"})
        df = ccm.collect("domain__c")

    fake_ctor.assert_called_once_with(
        username="user@example.com",
        password="pw",
        security_token="token",
        domain="test",
    )
    assert len(df) == 0


def test_custom_schema_file_overrides_default_manifest() -> None:
    fake_sf = MagicMock()
    fake_sf.query.return_value = {
        "totalSize": 1,
        "done": True,
        "records": [{"Id": "001", "Widget_Name__c": "Sprocket"}],
    }

    with patch("simple_salesforce.Salesforce", return_value=fake_sf):
        ccm = CCM(
            "salesforce",
            {**_CONFIG, "schema_file": str(FIXTURES / "custom_schema.json")},
        )

        assert "widget__c" in ccm.manifest
        assert "domain__c" not in ccm.manifest

        df = ccm.collect("widget__c")

    fake_sf.query.assert_called_once_with("select Id,Widget_Name__c from widget__c")
    assert len(df) == 1
    assert df.loc[0, "widget_name__c"] == "Sprocket"
