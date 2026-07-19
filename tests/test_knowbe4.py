import json

import responses

from posture import CCM


@responses.activate
def test_training_enrollments_pagination_stops_on_short_page() -> None:
    responses.add(
        responses.GET,
        "https://us.api.knowbe4.com/v1/training/enrollments",
        json=[{"enrollment_id": 1, "user": {"id": 1, "email": "a@example.com"}}],
        status=200,
    )

    ccm = CCM("knowbe4", {"api_token": "token"})
    df = ccm.collect("training_enrollments")

    assert len(df) == 1
    assert ccm.report("training_enrollments")["pages"] == 1


@responses.activate
def test_training_enrollments_follows_page_cursor() -> None:
    def callback(request):
        params = dict(
            pair.split("=") for pair in request.url.split("?", 1)[1].split("&")
        )
        page = params["page"]
        if page == "1":
            body = [{"enrollment_id": i, "user": {"id": i}} for i in range(500)]
        else:
            assert page == "2"
            body = [{"enrollment_id": 999, "user": {"id": 999}}]
        return (200, {}, json.dumps(body))

    responses.add_callback(
        responses.GET,
        "https://us.api.knowbe4.com/v1/training/enrollments",
        callback=callback,
        content_type="application/json",
    )

    ccm = CCM("knowbe4", {"api_token": "token"})
    df = ccm.collect("training_enrollments")

    assert len(df) == 501
    assert ccm.report("training_enrollments")["pages"] == 2


@responses.activate
def test_eu_region_routes_to_eu_base_url() -> None:
    responses.add(
        responses.GET,
        "https://eu.api.knowbe4.com/v1/training/enrollments",
        json=[],
        status=200,
    )

    ccm = CCM("knowbe4", {"api_token": "token", "region": "eu"})
    df = ccm.collect("training_enrollments")

    assert len(df) == 0


@responses.activate
def test_psts_pagination_stops_on_short_page() -> None:
    responses.add(
        responses.GET,
        "https://us.api.knowbe4.com/v1/phishing/security_tests",
        json=[{"pst_id": 301, "campaign_id": 201}],
        status=200,
    )

    ccm = CCM("knowbe4", {"api_token": "token"})
    df = ccm.collect("psts")

    assert len(df) == 1
    assert ccm.report("psts")["pages"] == 1


@responses.activate
def test_pst_recipients_fans_out_per_pst_id() -> None:
    responses.add(
        responses.GET,
        "https://us.api.knowbe4.com/v1/phishing/security_tests",
        json=[{"pst_id": 301}, {"pst_id": 302}],
        status=200,
    )
    responses.add(
        responses.GET,
        "https://us.api.knowbe4.com/v1/phishing/security_tests/301/recipients",
        json=[{"recipient_id": 1, "user": {"id": 501}}],
        status=200,
    )
    responses.add(
        responses.GET,
        "https://us.api.knowbe4.com/v1/phishing/security_tests/302/recipients",
        json=[{"recipient_id": 2, "user": {"id": 502}}],
        status=200,
    )

    ccm = CCM("knowbe4", {"api_token": "token"})
    df = ccm.collect("pst_recipients")

    assert len(df) == 2
    assert set(df["pst_id"]) == {301, 302}


@responses.activate
def test_pst_recipients_paginates_within_a_single_pst() -> None:
    responses.add(
        responses.GET,
        "https://us.api.knowbe4.com/v1/phishing/security_tests",
        json=[{"pst_id": 301}],
        status=200,
    )

    def callback(request):
        params = dict(
            pair.split("=") for pair in request.url.split("?", 1)[1].split("&")
        )
        page = params["page"]
        if page == "1":
            body = [{"recipient_id": i, "user": {"id": i}} for i in range(500)]
        else:
            assert page == "2"
            body = [{"recipient_id": 999, "user": {"id": 999}}]
        return (200, {}, json.dumps(body))

    responses.add_callback(
        responses.GET,
        "https://us.api.knowbe4.com/v1/phishing/security_tests/301/recipients",
        callback=callback,
        content_type="application/json",
    )

    ccm = CCM("knowbe4", {"api_token": "token"})
    df = ccm.collect("pst_recipients")

    assert len(df) == 501
    assert (df["pst_id"] == 301).all()


@responses.activate
def test_pst_recipients_empty_when_no_psts() -> None:
    responses.add(
        responses.GET,
        "https://us.api.knowbe4.com/v1/phishing/security_tests",
        json=[],
        status=200,
    )

    ccm = CCM("knowbe4", {"api_token": "token"})
    df = ccm.collect("pst_recipients")

    assert len(df) == 0
