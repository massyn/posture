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
