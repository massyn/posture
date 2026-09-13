import responses

from posture import CCM


@responses.activate
def test_alerts_paginates_via_from_offset() -> None:
    responses.add(
        responses.GET,
        "https://api.recordedfuture.com/alert/v3",
        json={
            "data": [{"id": "alert-1"}],
            "counts": {"returned": 1, "total": 2},
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.recordedfuture.com/alert/v3",
        json={
            "data": [{"id": "alert-2"}],
            "counts": {"returned": 1, "total": 2},
        },
        status=200,
    )

    ccm = CCM("recorded_future", {"token": "tok"})
    df = ccm.collect("alerts")

    assert list(df["id"]) == ["alert-1", "alert-2"]
    assert ccm.report("alerts")["pages"] == 2


@responses.activate
def test_alerts_forwards_vendor_kwargs() -> None:
    responses.add(
        responses.GET,
        "https://api.recordedfuture.com/alert/v3",
        json={"data": [{"id": "alert-1"}], "counts": {"returned": 1, "total": 1}},
        status=200,
    )

    ccm = CCM("recorded_future", {"token": "tok"})
    ccm.collect("alerts", statusInPortal="New", freetext="ransomware")

    request = responses.calls[0].request
    assert "statusInPortal=New" in request.url
    assert "freetext=ransomware" in request.url


@responses.activate
def test_vulnerability_risklist_parses_csv_and_evidence_details() -> None:
    csv_body = (
        '"Name","Risk","RiskString","EvidenceDetails"\n'
        '"CVE-2024-1234","89","8/25","[{""Rule"": ""Some Rule""}]"\n'
        '"CVE-2024-5678","25","1/25","[]"\n'
    )
    responses.add(
        responses.GET,
        "https://api.recordedfuture.com/vulnerability/risklist",
        body=csv_body,
        status=200,
        content_type="text/plain",
    )

    ccm = CCM("recorded_future", {"token": "tok"})
    df = ccm.collect("vulnerability_risklist")

    assert list(df["name"]) == ["CVE-2024-1234", "CVE-2024-5678"]
    assert int(df.loc[0, "risk"]) == 89
    assert df.loc[0, "evidence_details"] == '[{"Rule": "Some Rule"}]'


@responses.activate
def test_401_is_retried_then_propagates_as_incomplete_collection(monkeypatch) -> None:
    from posture.exceptions import IncompleteCollection

    monkeypatch.setattr("posture.base.time.sleep", lambda _seconds: None)

    responses.add(
        responses.GET,
        "https://api.recordedfuture.com/alert/v3",
        json={"error": "unauthorized"},
        status=401,
    )

    ccm = CCM("recorded_future", {"token": "bad-token"})

    try:
        ccm.collect("alerts")
        assert False, "expected IncompleteCollection"
    except IncompleteCollection:
        pass
