from urllib.parse import parse_qsl, urlparse

import responses

from posture import CCM

BASE_URL = "https://qualysapi.example.com"
POLICY_URL = BASE_URL + "/api/4.0/fo/compliance/policy/"
POSTURE_URL = BASE_URL + "/api/2.0/fo/compliance/posture/info/"
CONFIG = {"username": "u", "password": "p", "base_url": BASE_URL}

POLICY_XML = b"""<?xml version="1.0"?>
<POLICY_LIST_OUTPUT>
  <RESPONSE>
    <POLICY_LIST>
      <POLICY>
        <ID>100</ID>
        <TITLE><![CDATA[CIS Windows 2019]]></TITLE>
        <CREATED><DATETIME>2025-07-07T05:40:23Z</DATETIME><BY>admin</BY></CREATED>
        <STATUS><![CDATA[active]]></STATUS>
        <IS_LOCKED>0</IS_LOCKED>
        <CONTROL_LIST>
          <CONTROL>
            <ID>1071</ID>
            <STATEMENT><![CDATA[Minimum password length]]></STATEMENT>
            <CRITICALITY><LABEL>SERIOUS</LABEL><VALUE>3</VALUE></CRITICALITY>
            <STATUS><![CDATA[Active]]></STATUS>
          </CONTROL>
        </CONTROL_LIST>
      </POLICY>
      <POLICY>
        <ID>200</ID>
        <TITLE><![CDATA[CIS Ubuntu]]></TITLE>
      </POLICY>
    </POLICY_LIST>
  </RESPONSE>
</POLICY_LIST_OUTPUT>"""


def _posture_xml(posture_id: str, warning_url: str | None = None) -> bytes:
    warning = (
        f"<WARNING><CODE>1980</CODE><URL>{warning_url}</URL></WARNING>"
        if warning_url
        else ""
    )
    return f"""<?xml version="1.0"?>
<POSTURE_INFO_LIST_OUTPUT>
  <RESPONSE>
    <INFO_LIST>
      <INFO>
        <ID>{posture_id}</ID>
        <HOST_ID>3077710</HOST_ID>
        <CONTROL_ID>1071</CONTROL_ID>
        <TECHNOLOGY_ID>43</TECHNOLOGY_ID>
        <INSTANCE></INSTANCE>
        <STATUS>Failed</STATUS>
        <FIRST_FAIL_DATE>2026-09-01T10:00:00Z</FIRST_FAIL_DATE>
        <FIRST_PASS_DATE>N/A</FIRST_PASS_DATE>
      </INFO>
    </INFO_LIST>
    {warning}
  </RESPONSE>
</POSTURE_INFO_LIST_OUTPUT>""".encode()


def _params(request) -> dict:
    return dict(parse_qsl(urlparse(request.url).query))


@responses.activate
def test_policies_and_derived_controls() -> None:
    responses.add(responses.GET, POLICY_URL, body=POLICY_XML, content_type="text/xml")

    ccm = CCM("qualys", CONFIG)
    policies = ccm.collect("compliance_policies")
    controls = ccm.collect("compliance_policy_controls")

    assert list(policies["policy_id"]) == ["100", "200"]
    assert policies.loc[0, "title"] == "CIS Windows 2019"
    assert bool(policies.loc[0, "is_locked"]) is False
    assert policies.loc[0, "created_by"] == "admin"
    # A single CONTROL is still exploded as a one-element list.
    assert list(controls["control_id"]) == ["1071"]
    assert controls.loc[0, "policy_id"] == "100"
    assert controls.loc[0, "criticality_value"] == 3
    assert len(responses.calls) == 1  # controls replayed from the policy cache


@responses.activate
def test_posture_walks_every_policy_and_follows_warning_urls() -> None:
    responses.add(responses.GET, POLICY_URL, body=POLICY_XML, content_type="text/xml")

    def posture(request):
        params = _params(request)
        if params.get("policy_id") == "100":
            return (200, {}, _posture_xml("1", f"{POSTURE_URL}?page=2"))
        if params.get("page") == "2":
            return (200, {}, _posture_xml("2"))
        assert params["policy_id"] == "200"
        return (200, {}, _posture_xml("3"))

    responses.add_callback(
        responses.GET, POSTURE_URL, callback=posture, content_type="text/xml"
    )

    df = CCM("qualys", CONFIG).collect("compliance_posture")

    assert list(df["posture_id"]) == ["1", "2", "3"]
    assert list(df["policy_id"]) == ["100", "100", "200"]
    assert df.loc[0, "status"] == "Failed"
    assert df.loc[0, "first_failed"].isoformat() == "2026-09-01T10:00:00+00:00"
    assert df["first_passed"].isna().all()


@responses.activate
def test_policy_ids_kwarg_skips_policy_list_and_passes_filters() -> None:
    def posture(request):
        params = _params(request)
        assert params["policy_id"] == "200"
        assert params["status"] == "Failed"
        return (200, {}, _posture_xml("9"))

    responses.add_callback(
        responses.GET, POSTURE_URL, callback=posture, content_type="text/xml"
    )

    df = CCM("qualys", CONFIG).collect(
        "compliance_posture", policy_ids=[200], status="Failed"
    )

    assert list(df["policy_id"]) == ["200"]
    assert all(POLICY_URL not in call.request.url for call in responses.calls)
