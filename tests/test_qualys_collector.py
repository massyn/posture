import pytest
import responses

from posture import CCM
from posture.collectors.qualys.assets import gateway_url_for
from posture.exceptions import IncompleteCollection

BASE_URL = "https://qualysapi.qg2.apps.qualys.com"
CONFIG = {"username": "u", "password": "p", "base_url": BASE_URL}
HOSTS_URL = BASE_URL + "/api/5.0/fo/asset/host/"
FINDING_URL = BASE_URL + "/qps/rest/3.0/search/was/finding"

HOSTS_XML = b"""<?xml version="1.0"?>
<HOST_LIST_OUTPUT>
  <RESPONSE>
    <HOST_LIST><HOST><ID>1</ID><IP>10.0.0.1</IP></HOST></HOST_LIST>
  </RESPONSE>
</HOST_LIST_OUTPUT>"""


@pytest.mark.parametrize(
    ("api_server", "gateway"),
    [
        ("https://qualysapi.qualys.com", "https://gateway.qg1.apps.qualys.com"),
        ("https://qualysapi.qualys.eu", "https://gateway.qg1.apps.qualys.eu"),
        (
            "https://qualysapi.qg3.apps.qualys.com",
            "https://gateway.qg3.apps.qualys.com",
        ),
        (
            "https://qualysapi.qg1.apps.qualys.com.au",
            "https://gateway.qg1.apps.qualys.com.au",
        ),
        ("https://qualys.example.internal", None),
    ],
)
def test_gateway_url_is_derived_from_the_api_server(api_server, gateway) -> None:
    assert gateway_url_for(api_server) == gateway


@responses.activate
def test_explicit_gateway_url_overrides_the_derived_one() -> None:
    gateway = "https://gateway.private.example.com"
    responses.add(responses.POST, gateway + "/auth", body="jwt", status=201)
    responses.add(
        responses.POST,
        gateway + "/rest/2.0/search/am/asset",
        json={"responseCode": "SUCCESS", "hasMore": 0, "assetListData": {}},
    )

    CCM("qualys", {**CONFIG, "gateway_url": "gateway.private.example.com"}).collect(
        "assets"
    )

    assert [call.request.url.split("?")[0] for call in responses.calls] == [
        gateway + "/auth",
        gateway + "/rest/2.0/search/am/asset",
    ]


def test_underivable_gateway_fails_only_the_asset_tables() -> None:
    ccm = CCM("qualys", {**CONFIG, "base_url": "https://qualys.example.internal"})

    with pytest.raises(IncompleteCollection, match="QUALYS_GATEWAY_URL"):
        ccm.collect("assets")


@responses.activate
def test_unlicensed_module_fails_its_table_and_not_the_others() -> None:
    # TotalAppSec not on the subscription: its table fails, VMDR still
    # collects on the same instance, and the gateway is never logged in to.
    responses.add(
        responses.POST,
        FINDING_URL,
        json={
            "ServiceResponse": {
                "responseCode": "UNAUTHORIZED",
                "responseErrorDetails": {"errorMessage": "No WAS module"},
            }
        },
    )
    responses.add(responses.GET, HOSTS_URL, body=HOSTS_XML, content_type="text/xml")

    ccm = CCM("qualys", CONFIG)
    with pytest.raises(IncompleteCollection, match="No WAS module"):
        ccm.collect("webapps_findings")
    hosts = ccm.collect("vm_hosts")

    assert list(hosts["host_id"]) == ["1"]
    assert all("gateway" not in call.request.url for call in responses.calls)
