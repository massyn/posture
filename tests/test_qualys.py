from urllib.parse import parse_qsl, urlparse

import responses

from posture import CCM, IncompleteCollection

BASE_URL = "https://qualysapi.example.com"
HOSTS_URL = BASE_URL + "/api/5.0/fo/asset/host/"

PAGE1_XML = f"""<?xml version="1.0"?>
<HOST_LIST_OUTPUT>
  <RESPONSE>
    <HOST_LIST>
      <HOST><ID>1</ID><IP>10.0.0.1</IP></HOST>
    </HOST_LIST>
    <WARNING>
      <CODE>1980</CODE>
      <URL>{HOSTS_URL}?action=list&amp;id_min=2</URL>
    </WARNING>
  </RESPONSE>
</HOST_LIST_OUTPUT>""".encode()

PAGE2_XML = b"""<?xml version="1.0"?>
<HOST_LIST_OUTPUT>
  <RESPONSE>
    <HOST_LIST>
      <HOST><ID>2</ID><IP>10.0.0.2</IP></HOST>
    </HOST_LIST>
  </RESPONSE>
</HOST_LIST_OUTPUT>"""

VULN_KB_XML = b"""<?xml version="1.0"?>
<KNOWLEDGE_BASE_VULN_LIST_OUTPUT>
  <RESPONSE>
    <VULN_LIST>
      <VULN><QID>38170</QID><TITLE>OpenSSL RCE</TITLE></VULN>
    </VULN_LIST>
  </RESPONSE>
</KNOWLEDGE_BASE_VULN_LIST_OUTPUT>"""


def _params(request) -> dict:
    return dict(parse_qsl(urlparse(request.url).query))


@responses.activate
def test_hosts_pagination_follows_warning_url_cursor() -> None:
    def callback(request):
        params = _params(request)
        if "id_min" not in params:
            return (200, {}, PAGE1_XML)
        assert params["id_min"] == "2"
        return (200, {}, PAGE2_XML)

    responses.add_callback(
        responses.GET, HOSTS_URL, callback=callback, content_type="text/xml"
    )

    ccm = CCM(
        "qualys",
        {"username": "u", "password": "p", "base_url": BASE_URL},
    )
    df = ccm.collect("hosts")

    assert len(df) == 2
    assert set(df["host_id"]) == {"1", "2"}
    assert ccm.report("hosts")["pages"] == 2


@responses.activate
def test_persistent_401_raises_incomplete_collection_not_a_crash() -> None:
    # Basic auth has no separate login call to validate credentials against —
    # a bad username/password only surfaces once the first real request 401s,
    # and base.py retries re-authentication a bounded number of times before
    # giving up. It must give up cleanly (IncompleteCollection), not raise
    # the raw HTTPError/UnauthorizedSignal.
    responses.add(responses.GET, HOSTS_URL, status=401)

    ccm = CCM(
        "qualys",
        {"username": "u", "password": "wrong", "base_url": BASE_URL},
    )

    try:
        ccm.collect("hosts")
        assert False, "expected IncompleteCollection"
    except IncompleteCollection as exc:
        assert exc.source == "qualys"
        assert exc.resource == "hosts"


@responses.activate
def test_409_concurrency_limit_is_retried_with_wait_header(monkeypatch) -> None:
    monkeypatch.setattr("posture.base.time.sleep", lambda _s: None)

    call_count = 0

    def callback(request):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return (409, {"X-RateLimit-ToWait-Sec": "1"}, b"")
        return (200, {}, PAGE2_XML)

    responses.add_callback(
        responses.GET, HOSTS_URL, callback=callback, content_type="text/xml"
    )

    ccm = CCM(
        "qualys",
        {"username": "u", "password": "p", "base_url": BASE_URL},
    )
    df = ccm.collect("hosts")

    assert len(df) == 1
    assert df.loc[0, "host_id"] == "2"
    assert ccm.report("hosts")["rate_limited_count"] == 1


@responses.activate
def test_exhausted_window_paces_next_request_before_firing(monkeypatch) -> None:
    sleep_calls = []
    monkeypatch.setattr(
        "posture.collectors.qualys.time.sleep", lambda s: sleep_calls.append(s)
    )

    call_count = 0

    def callback(request):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            headers = {"X-RateLimit-Remaining": "0", "X-RateLimit-ToWait-Sec": "5"}
            return (200, {**headers}, PAGE1_XML)
        return (200, {}, PAGE2_XML)

    responses.add_callback(
        responses.GET, HOSTS_URL, callback=callback, content_type="text/xml"
    )

    ccm = CCM(
        "qualys",
        {"username": "u", "password": "p", "base_url": BASE_URL},
    )
    df = ccm.collect("hosts")

    # first request reports the window exhausted -> the second request (the
    # id_min=2 follow-up page) must be paced before firing, not sent
    # immediately and left to be reactively 409'd.
    assert sleep_calls == [5.0]
    assert len(df) == 2


@responses.activate
def test_vulnerabilities_kb_request_omits_truncation_limit() -> None:
    # KnowledgeBase (/api/4.0/fo/knowledge_base/vuln/) isn't a truncated list
    # API like asset/host/* — sending truncation_limit gets a 400 back.
    kb_url = BASE_URL + "/api/4.0/fo/knowledge_base/vuln/"

    def callback(request):
        params = _params(request)
        assert "truncation_limit" not in params
        return (200, {}, VULN_KB_XML)

    responses.add_callback(
        responses.GET, kb_url, callback=callback, content_type="text/xml"
    )

    ccm = CCM(
        "qualys",
        {"username": "u", "password": "p", "base_url": BASE_URL},
    )
    df = ccm.collect("vulnerabilities")

    assert len(df) == 1
    assert df.loc[0, "qid"] == "38170"


@responses.activate
def test_vulnerabilities_kwargs_override_built_in_defaults() -> None:
    # Operators must be able to narrow a KnowledgeBase pull (e.g. to a QID
    # range or a tighter `details` scope) at their discretion — kwargs win
    # over this collector's own defaults for the same param name.
    kb_url = BASE_URL + "/api/4.0/fo/knowledge_base/vuln/"
    seen_params: dict[str, str] = {}

    def callback(request):
        nonlocal seen_params
        seen_params = _params(request)
        return (200, {}, VULN_KB_XML)

    responses.add_callback(
        responses.GET, kb_url, callback=callback, content_type="text/xml"
    )

    ccm = CCM(
        "qualys",
        {"username": "u", "password": "p", "base_url": BASE_URL},
    )
    ccm.collect("vulnerabilities", details="Basic", ids="38170")

    assert seen_params["details"] == "Basic"
    assert seen_params["ids"] == "38170"


@responses.activate
def test_409_registration_error_fails_immediately_without_retrying() -> None:
    # Qualys reuses 409 for a permanent "account not registered" error
    # (CODE 2003), not just its concurrency limit. That must fail the
    # collection outright, not burn the rate-limit retry budget treating it
    # as throttling.
    call_count = 0
    body = b"""<?xml version="1.0"?>
<SIMPLE_RETURN>
  <RESPONSE>
    <CODE>2003</CODE>
    <TEXT>Registration must be completed before API requests will be served
    for this account: https://qualysguard.example.com/fo/</TEXT>
  </RESPONSE>
</SIMPLE_RETURN>"""

    def callback(request):
        nonlocal call_count
        call_count += 1
        return (409, {}, body)

    responses.add_callback(
        responses.GET, HOSTS_URL, callback=callback, content_type="text/xml"
    )

    ccm = CCM(
        "qualys",
        {"username": "u", "password": "p", "base_url": BASE_URL},
    )

    try:
        ccm.collect("hosts")
        assert False, "expected IncompleteCollection"
    except IncompleteCollection as exc:
        assert "2003" in str(exc)
        assert "Registration must be completed" in str(exc)

    # exactly one request — no rate-limit retry loop for a fatal 409
    assert call_count == 1


@responses.activate
def test_409_single_instance_limit_fails_immediately_without_retrying() -> None:
    # CODE 1960 = "This API cannot be run again until N currently running
    # instance(s) have finished" — another run of the same API is already in
    # flight on this account. This process has no way to wait it out, so it
    # must fail the collection outright, not burn the rate-limit retry budget.
    call_count = 0
    body = b"""<?xml version="1.0"?>
<SIMPLE_RETURN>
  <RESPONSE>
    <DATETIME>2026-07-21T21:08:51Z</DATETIME>
    <CODE>1960</CODE>
    <TEXT>This API cannot be run again until 1 currently running instance has finished.</TEXT>
    <ITEM_LIST>
      <ITEM>
        <KEY>CALLS_TO_FINISH</KEY>
        <VALUE>1</VALUE>
      </ITEM>
    </ITEM_LIST>
  </RESPONSE>
</SIMPLE_RETURN>"""

    def callback(request):
        nonlocal call_count
        call_count += 1
        return (409, {}, body)

    responses.add_callback(
        responses.GET, HOSTS_URL, callback=callback, content_type="text/xml"
    )

    ccm = CCM(
        "qualys",
        {"username": "u", "password": "p", "base_url": BASE_URL},
    )

    try:
        ccm.collect("hosts")
        assert False, "expected IncompleteCollection"
    except IncompleteCollection as exc:
        assert "1960" in str(exc)
        assert "currently running instance" in str(exc)

    # exactly one request — no rate-limit retry loop for a fatal 409
    assert call_count == 1
