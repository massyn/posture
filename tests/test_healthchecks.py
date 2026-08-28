import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
import responses

from posture import CCM
from posture.exceptions import IncompleteCollection

FIXTURES = Path(__file__).parent / "fixtures" / "healthchecks"
CHECKS_URL = "https://healthchecks.io/api/v3/checks/"


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def _add_flips(unique_key: str, body: dict) -> None:
    responses.add(
        responses.GET,
        f"https://healthchecks.io/api/v3/checks/{unique_key}/flips/",
        json=body,
    )


@responses.activate
def test_checks_single_unpaginated_call() -> None:
    responses.add(responses.GET, CHECKS_URL, json=_fixture("checks.json"))

    df = CCM("healthchecks", {"token": "hcr_x"}).collect("checks")

    assert list(df["name"]) == ["do3-heartbeat", "nightly-backup"]
    assert df.loc[1, "schedule"] == "0 2 * * *"
    assert responses.calls[0].request.headers["X-Api-Key"] == "hcr_x"


@responses.activate
def test_checks_slug_and_tag_filters_pass_through() -> None:
    responses.add(responses.GET, CHECKS_URL, json={"checks": []})

    CCM("healthchecks", {"token": "k"}).collect(
        "checks", slug="do3-heartbeat", tag="prod"
    )

    qs = parse_qs(urlparse(responses.calls[0].request.url).query)
    assert qs["slug"] == ["do3-heartbeat"]
    assert qs["tag"] == ["prod"]


@responses.activate
def test_flips_fan_out_default_window_is_90_days() -> None:
    responses.add(responses.GET, CHECKS_URL, json=_fixture("checks.json"))
    _add_flips(
        "ea3b76a8041eee6ae48b08e567664a62fcef7768", _fixture("flips_heartbeat.json")
    )
    _add_flips("a9536b7b8a6daee3817fb9610a54518c103da327", {"flips": []})

    df = CCM("healthchecks", {"token": "k"}).collect("flips")

    assert len(df) == 2
    assert list(df["up"]) == [1, 0]
    assert set(df["check_name"]) == {"do3-heartbeat"}

    flip_calls = [c for c in responses.calls if "/flips/" in c.request.url]
    assert len(flip_calls) == 2
    for call in flip_calls:
        qs = parse_qs(urlparse(call.request.url).query)
        assert qs["seconds"] == [str(90 * 24 * 3600)]


@responses.activate
def test_flips_window_hours_override() -> None:
    responses.add(responses.GET, CHECKS_URL, json=_fixture("checks.json"))
    _add_flips("ea3b76a8041eee6ae48b08e567664a62fcef7768", {"flips": []})
    _add_flips("a9536b7b8a6daee3817fb9610a54518c103da327", {"flips": []})

    CCM("healthchecks", {"token": "k"}).collect("flips", flips_window_hours=6)

    flip_call = next(c for c in responses.calls if "/flips/" in c.request.url)
    qs = parse_qs(urlparse(flip_call.request.url).query)
    assert qs["seconds"] == [str(6 * 3600)]


@responses.activate
def test_flips_since_datetime_uses_start_param() -> None:
    responses.add(responses.GET, CHECKS_URL, json=_fixture("checks.json"))
    _add_flips("ea3b76a8041eee6ae48b08e567664a62fcef7768", {"flips": []})
    _add_flips("a9536b7b8a6daee3817fb9610a54518c103da327", {"flips": []})

    CCM("healthchecks", {"token": "k"}).collect("flips", start="2026-01-01T00:00:00Z")

    flip_call = next(c for c in responses.calls if "/flips/" in c.request.url)
    qs = parse_qs(urlparse(flip_call.request.url).query)
    assert qs["start"] == ["1767225600"]
    assert "seconds" not in qs


@responses.activate
def test_flips_rejects_conflicting_window_kwargs() -> None:
    responses.add(responses.GET, CHECKS_URL, json=_fixture("checks.json"))

    with pytest.raises((ValueError, IncompleteCollection)):
        CCM("healthchecks", {"token": "k"}).collect(
            "flips", flips_window_hours=6, seconds=100
        )


@responses.activate
def test_unauthorized_raises_incomplete_collection() -> None:
    responses.add(
        responses.GET, CHECKS_URL, json={"error": "wrong api key"}, status=401
    )

    with pytest.raises(IncompleteCollection):
        CCM("healthchecks", {"token": "bad"}).collect("checks")


@responses.activate
def test_self_hosted_api_url_is_normalised_and_used() -> None:
    responses.add(
        responses.GET,
        "https://hc.internal.example.com/api/v3/checks/",
        json={"checks": []},
    )

    CCM(
        "healthchecks",
        {"token": "k", "api_url": "hc.internal.example.com/"},
    ).collect("checks")

    assert responses.calls[0].request.url.startswith(
        "https://hc.internal.example.com/api/v3/checks/"
    )
