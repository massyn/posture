from pathlib import Path
from urllib.parse import parse_qs

import pytest
import responses

from posture import CCM
from posture.collectors.bigfix import _QUERIES, MANIFEST
from posture.exceptions import IncompleteCollection

_QUERY_URL = "https://bigfix.example.com:52311/api/query"
_CONFIG = {
    "endpoint": "bigfix.example.com:52311",
    "username": "ccm",
    "password": "secret",
}


def _relevance(call: responses.Call) -> str:
    return parse_qs(call.request.body)["relevance"][0]


def test_every_manifest_column_is_a_query_field() -> None:
    for resource, spec in MANIFEST.items():
        fields = {name for name, _ in _QUERIES[resource][0]}
        paths = {column[0] for column in spec["columns"].values()}
        assert paths == fields, resource


@responses.activate
def test_computers_tuples_become_typed_columns() -> None:
    responses.add(
        responses.POST,
        _QUERY_URL,
        json={
            "result": [
                [
                    101,
                    "host-1",
                    "Win2019 10.0.17763",
                    "2400 MHz Xeon",
                    "Server",
                    "Native",
                    "11.0.6.300",
                    "10.0.0.1, 10.0.0.2",
                    "alice",
                    "relay.example.com",
                    False,
                    "Tue, 13 Oct 2026 10:00:00 +0000",
                ],
                [102, "", "", "", "", "", "", "", "", "", True, ""],
            ],
            "plural": True,
            "type": "( integer, string, ... )",
            "evaltime_ms": 1.2,
        },
        status=200,
    )

    ccm = CCM("bigfix", _CONFIG)
    df = ccm.collect("computers")

    assert list(df["id"]) == [101, 102]
    assert df.loc[0, "operating_system"] == "Win2019 10.0.17763"
    assert df.loc[0, "ip_addresses"] == "10.0.0.1, 10.0.0.2"
    assert list(df["locked"]) == [False, True]
    assert df.loc[0, "last_report_time"].isoformat() == "2026-10-13T10:00:00+00:00"
    assert df["last_report_time"].isna().iloc[1]

    request = responses.calls[0].request
    assert request.params == {"output": "json"}
    assert _relevance(responses.calls[0]).endswith("of bes computers whose (true)")
    assert request.req_kwargs["verify"] is True


@responses.activate
def test_fixlet_results_parse_relevance_times() -> None:
    responses.add(
        responses.POST,
        _QUERY_URL,
        json={
            "result": [
                [
                    101,
                    "host-1",
                    42,
                    "Enterprise Security",
                    "MS26-001: Security Update",
                    "Critical",
                    "Mon, 05 Oct 2026 08:30:00 +1000",
                    "",
                ]
            ],
            "plural": True,
            "type": "( integer, ... )",
        },
        status=200,
    )

    df = CCM("bigfix", _CONFIG).collect("fixlet_results")

    assert df.loc[0, "fixlet_id"] == 42
    assert df.loc[0, "source_severity"] == "Critical"
    assert df.loc[0, "first_became_relevant"].isoformat() == "2026-10-04T22:30:00+00:00"
    assert df["last_became_relevant"].isna().iloc[0]


@responses.activate
def test_fixlets_source_release_date_is_a_datetime() -> None:
    responses.add(
        responses.POST,
        _QUERY_URL,
        json={
            "result": [
                [
                    42,
                    "Enterprise Security",
                    "MS26-001: Security Update",
                    "Security Update",
                    "Microsoft",
                    "MS26-001",
                    "Critical",
                    "Tue, 13 Oct 2026",
                    "CVE-2026-0001, CVE-2026-0002",
                    7,
                ]
            ],
            "plural": True,
        },
        status=200,
    )

    df = CCM("bigfix", _CONFIG).collect("fixlets")

    assert df.loc[0, "source_release_date"].isoformat() == "2026-10-13T00:00:00+00:00"
    assert df.loc[0, "applicable_computer_count"] == 7


@responses.activate
def test_whose_kwarg_is_anded_onto_the_default_filter() -> None:
    responses.add(
        responses.POST, _QUERY_URL, json={"result": [], "plural": True}, status=200
    )

    df = CCM("bigfix", _CONFIG).collect(
        "fixlets", whose='source severity of it = "Critical"'
    )

    assert len(df) == 0
    assert "applicable_computer_count" in df.columns
    assert _relevance(responses.calls[0]).endswith(
        "of bes fixlets whose (fixlet flag of it and applicable computer count of "
        'it > 0 and (source severity of it = "Critical"))'
    )


def test_unknown_kwarg_raises() -> None:
    ccm = CCM("bigfix", _CONFIG)
    with pytest.raises(IncompleteCollection, match="Unsupported kwargs"):
        ccm.collect("computers", relevance="names of bes sites")


@responses.activate
def test_unauthorized_raises_incomplete_collection() -> None:
    responses.add(responses.POST, _QUERY_URL, status=401)

    ccm = CCM("bigfix", _CONFIG)
    with pytest.raises(IncompleteCollection):
        ccm.collect("computers")


@responses.activate
@pytest.mark.parametrize("insecure", ["true", True])
def test_insecure_disables_certificate_verification(insecure: object) -> None:
    responses.add(
        responses.POST, _QUERY_URL, json={"result": [], "plural": True}, status=200
    )

    CCM("bigfix", {**_CONFIG, "insecure": insecure}).collect("computers")

    assert responses.calls[0].request.req_kwargs["verify"] is False


@responses.activate
def test_ca_bundle_is_used_for_verification(tmp_path: Path) -> None:
    bundle = tmp_path / "bigfix-ca.pem"
    bundle.write_text("-----BEGIN CERTIFICATE-----\n")
    responses.add(
        responses.POST, _QUERY_URL, json={"result": [], "plural": True}, status=200
    )

    CCM("bigfix", {**_CONFIG, "ca_bundle": str(bundle)}).collect("computers")

    assert responses.calls[0].request.req_kwargs["verify"] == str(bundle)


def test_ca_bundle_must_exist(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="ca_bundle"):
        CCM("bigfix", {**_CONFIG, "ca_bundle": str(tmp_path / "missing.pem")})


def test_insecure_and_ca_bundle_are_mutually_exclusive(tmp_path: Path) -> None:
    bundle = tmp_path / "bigfix-ca.pem"
    bundle.write_text("")
    with pytest.raises(ValueError, match="mutually exclusive"):
        CCM("bigfix", {**_CONFIG, "insecure": "true", "ca_bundle": str(bundle)})


def test_invalid_insecure_value_raises() -> None:
    with pytest.raises(ValueError, match="insecure"):
        CCM("bigfix", {**_CONFIG, "insecure": "maybe"})
