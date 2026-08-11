import requests
import responses

from posture import CCM


@responses.activate
def test_collector_follows_x_cs_region_to_correct_base_url() -> None:
    responses.add(
        responses.POST,
        "https://api.crowdstrike.com/oauth2/token",
        json={"access_token": "tok", "expires_in": 1800},
        headers={"X-Cs-Region": "us-2"},
        status=201,
    )
    responses.add(
        responses.POST,
        "https://api.us-2.crowdstrike.com/identity-protection/combined/graphql/v1",
        json={"data": {"entities": {"nodes": [], "pageInfo": {"hasNextPage": False}}}},
        status=200,
    )

    ccm = CCM("crowdstrike_identity", {"client_id": "id", "client_secret": "secret"})
    df = ccm.collect("entities")

    assert len(df) == 0
    assert len(responses.calls) == 2


@responses.activate
def test_transient_connection_error_is_retried(monkeypatch) -> None:
    monkeypatch.setattr("posture.base.time.sleep", lambda _seconds: None)

    responses.add(
        responses.POST,
        "https://api.crowdstrike.com/oauth2/token",
        json={"access_token": "tok", "expires_in": 1800},
        headers={"X-Cs-Region": "us-1"},
        status=201,
    )
    responses.add(
        responses.POST,
        "https://api.crowdstrike.com/identity-protection/combined/graphql/v1",
        body=requests.exceptions.ConnectionError("connection reset"),
    )
    responses.add(
        responses.POST,
        "https://api.crowdstrike.com/identity-protection/combined/graphql/v1",
        json={"data": {"entities": {"nodes": [], "pageInfo": {"hasNextPage": False}}}},
        status=200,
    )

    ccm = CCM("crowdstrike_identity", {"client_id": "id", "client_secret": "secret"})
    df = ccm.collect("entities")

    assert len(df) == 0
    assert ccm.report("entities")["retries"] == 1


@responses.activate
def test_entities_parses_nodes_and_derived_risk_factors() -> None:
    responses.add(
        responses.POST,
        "https://api.crowdstrike.com/oauth2/token",
        json={"access_token": "tok", "expires_in": 1800},
        headers={"X-Cs-Region": "us-1"},
        status=201,
    )
    responses.add(
        responses.POST,
        "https://api.crowdstrike.com/identity-protection/combined/graphql/v1",
        json={
            "data": {
                "entities": {
                    "nodes": [
                        {
                            "entityId": "ent-1",
                            "primaryDisplayName": "jdoe",
                            "type": "USER",
                            "riskScore": 80,
                            "riskScoreSeverity": "HIGH",
                            "riskFactors": [
                                {"type": "STALE_PASSWORD", "severity": "HIGH"}
                            ],
                        }
                    ],
                    "pageInfo": {"hasNextPage": False},
                }
            }
        },
        status=200,
    )

    ccm = CCM("crowdstrike_identity", {"client_id": "id", "client_secret": "secret"})
    entities_df = ccm.collect("entities")
    risk_factors_df = ccm.collect("entity_risk_factors")

    assert entities_df.loc[0, "risk_score_severity"] == "HIGH"
    assert risk_factors_df.loc[0, "entity_id"] == "ent-1"
    assert risk_factors_df.loc[0, "type"] == "STALE_PASSWORD"


@responses.activate
def test_detections_batches_composite_ids_from_query_then_entities() -> None:
    responses.add(
        responses.POST,
        "https://api.crowdstrike.com/oauth2/token",
        json={"access_token": "tok", "expires_in": 1800},
        headers={"X-Cs-Region": "us-1"},
        status=201,
    )
    responses.add(
        responses.GET,
        "https://api.crowdstrike.com/alerts/queries/alerts/v2",
        json={
            "resources": ["det-1"],
            "meta": {"pagination": {"total": 1, "offset": 1}},
        },
        status=200,
    )
    responses.add(
        responses.POST,
        "https://api.crowdstrike.com/alerts/entities/alerts/v2",
        json={
            "resources": [
                {"id": "det-1", "product": "idp", "severity_name": "critical"}
            ]
        },
        status=200,
    )

    ccm = CCM("crowdstrike_identity", {"client_id": "id", "client_secret": "secret"})
    df = ccm.collect("detections")

    assert len(df) == 1
    assert df.loc[0, "severity_name"] == "critical"
