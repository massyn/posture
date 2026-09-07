import pandas as pd
import requests
import responses

from posture import CCM


@responses.activate
def test_no_hosts_configured_makes_no_network_call() -> None:
    ccm = CCM("http")
    df = ccm.collect("headers")

    assert len(df) == 0
    assert list(df.columns) == [
        "host",
        "ok",
        "status_code",
        "secure",
        "tls_error",
        "error",
        "duration_ms",
        "header_name",
        "header_value",
        "_collected_at",
    ]
    assert ccm.report("headers")["records"] == 0
    assert len(responses.calls) == 0


@responses.activate
def test_headers_returned_as_tidy_long_rows() -> None:
    responses.add(
        responses.GET,
        "https://example.com",
        headers={"Content-Type": "text/html", "X-Frame-Options": "DENY"},
        status=200,
    )

    ccm = CCM("http")
    df = ccm.collect("headers", hosts=["https://example.com"])

    assert set(df["header_name"]) == {"Content-Type", "X-Frame-Options"}
    assert (df["host"] == "https://example.com").all()
    assert (df["ok"]).all()
    assert (df["status_code"] == 200).all()
    assert bool(df["secure"].iloc[0]) is True
    assert df["tls_error"].isna().all()
    row = df.loc[df["header_name"] == "X-Frame-Options"].iloc[0]
    assert row["header_value"] == "DENY"


@responses.activate
def test_http_scheme_leaves_secure_null() -> None:
    responses.add(responses.GET, "http://neverssl.com", headers={"A": "b"}, status=200)

    ccm = CCM("http")
    df = ccm.collect("headers", hosts=["http://neverssl.com"])

    assert df["secure"].isna().all()


@responses.activate
def test_redirect_is_not_followed_and_location_is_a_header_row() -> None:
    responses.add(
        responses.GET,
        "https://example.com",
        headers={"Location": "https://www.example.com/"},
        status=301,
    )

    ccm = CCM("http")
    df = ccm.collect("headers", hosts=["https://example.com"])

    assert len(responses.calls) == 1
    assert (df["status_code"] == 301).all()
    location = df.loc[df["header_name"] == "Location"].iloc[0]
    assert location["header_value"] == "https://www.example.com/"


@responses.activate
def test_per_host_failure_is_a_row_not_an_exception() -> None:
    responses.add(
        responses.GET,
        "https://good.example",
        headers={"Server": "nginx"},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://bad.example",
        body=requests.exceptions.ConnectionError("name resolution failed"),
    )

    ccm = CCM("http")
    df = ccm.collect("headers", hosts=["https://good.example", "https://bad.example"])

    good = df.loc[df["host"] == "https://good.example"]
    bad = df.loc[df["host"] == "https://bad.example"]
    assert good["ok"].all()
    assert bool(bad["ok"].iloc[0]) is False
    assert len(bad) == 1
    assert pd.isna(bad["header_name"].iloc[0])
    assert "name resolution failed" in bad["error"].iloc[0]
    assert pd.isna(bad["status_code"].iloc[0])


@responses.activate
def test_tls_verification_failure_falls_back_to_insecure() -> None:
    responses.add(
        responses.GET,
        "https://self-signed.example",
        body=requests.exceptions.SSLError("certificate verify failed: self-signed"),
    )
    responses.add(
        responses.GET,
        "https://self-signed.example",
        headers={"Server": "Apache"},
        status=200,
    )

    ccm = CCM("http")
    df = ccm.collect("headers", hosts=["https://self-signed.example"])

    assert len(responses.calls) == 2
    assert bool(df["secure"].iloc[0]) is False
    assert "self-signed" in df["tls_error"].iloc[0]
    assert df["ok"].all()
    assert (df["header_name"] == "Server").any()


@responses.activate
def test_host_without_scheme_is_a_failure_row_not_an_exception() -> None:
    responses.add(responses.GET, "https://ok.example", headers={"A": "b"}, status=200)

    ccm = CCM("http")
    df = ccm.collect("headers", hosts=["example.com", "https://ok.example"])

    bad = df.loc[df["host"] == "example.com"]
    assert len(bad) == 1
    assert bool(bad["ok"].iloc[0]) is False
    assert "scheme" in bad["error"].iloc[0]
    assert pd.isna(bad["header_name"].iloc[0])
    assert df.loc[df["host"] == "https://ok.example", "ok"].all()


@responses.activate
def test_hosts_kwarg_overrides_configured_default() -> None:
    responses.add(
        responses.GET, "https://kwarg.example", headers={"A": "b"}, status=200
    )

    ccm = CCM("http", {"hosts": "https://config.example"})
    df = ccm.collect("headers", hosts=["https://kwarg.example"])

    assert len(responses.calls) == 1
    assert (df["host"] == "https://kwarg.example").all()
