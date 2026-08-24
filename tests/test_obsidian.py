import responses

from posture import CCM

_ENDPOINT = "https://api.obsec.io/v1/gql"


@responses.activate
def test_posture_rules_pagination_follows_cursor() -> None:
    responses.add(
        responses.POST,
        _ENDPOINT,
        json={
            "data": {
                "listGlobalPostureRules": {
                    "has_more_results": True,
                    "cursor": "abc",
                    "rules": [{"rule_id": "R1", "name": "Rule One"}],
                    "total": 2,
                }
            }
        },
        status=200,
    )
    responses.add(
        responses.POST,
        _ENDPOINT,
        json={
            "data": {
                "listGlobalPostureRules": {
                    "has_more_results": False,
                    "cursor": None,
                    "rules": [{"rule_id": "R2", "name": "Rule Two"}],
                    "total": 2,
                }
            }
        },
        status=200,
    )

    ccm = CCM("obsidian", {"token": "tok"})
    df = ccm.collect("posture_rules")

    assert list(df["rule_id"]) == ["R1", "R2"]
    assert ccm.report("posture_rules")["pages"] == 2


@responses.activate
def test_posture_rule_tenant_states_explodes_nested_list() -> None:
    responses.add(
        responses.POST,
        _ENDPOINT,
        json={
            "data": {
                "listGlobalPostureRules": {
                    "has_more_results": False,
                    "cursor": None,
                    "rules": [
                        {
                            "rule_id": "R1",
                            "tenant_states": [
                                {
                                    "tenant_id": "T1",
                                    "is_passing": False,
                                    "violations": 3,
                                    "tenant": {"name": "Acme", "platform": "o365"},
                                }
                            ],
                        }
                    ],
                    "total": 1,
                }
            }
        },
        status=200,
    )

    ccm = CCM("obsidian", {"token": "tok"})
    df = ccm.collect("posture_rule_tenant_states")

    assert df.loc[0, "rule_id"] == "R1"
    assert df.loc[0, "tenant_id"] == "T1"
    assert bool(df.loc[0, "is_passing"]) is False
    assert df.loc[0, "tenant_name"] == "Acme"


@responses.activate
def test_posture_scores_flattens_both_groupings() -> None:
    responses.add(
        responses.POST,
        _ENDPOINT,
        json={
            "data": {
                "listGroupedPostureScoresPlatforms": {
                    "has_more_results": False,
                    "cursor": None,
                    "scores": [
                        {
                            "start_datetime": "2026-08-24T00:00:00.000Z",
                            "end_datetime": "2026-08-25T00:00:00.000Z",
                            "scores": {"o365": {"score": 82}},
                        }
                    ],
                },
                "listGroupedPostureScoresCompliance": {
                    "has_more_results": False,
                    "cursor": None,
                    "scores": [
                        {
                            "start_datetime": "2026-08-24T00:00:00.000Z",
                            "end_datetime": "2026-08-25T00:00:00.000Z",
                            "scores": {"soc2": {"score": 91}},
                        }
                    ],
                },
            }
        },
        status=200,
    )

    ccm = CCM("obsidian", {"token": "tok"})
    df = ccm.collect("posture_scores")

    assert set(df["group_by"]) == {"platforms", "standards"}
    assert set(df["key"]) == {"o365", "soc2"}
    import json

    o365_row = df[df["key"] == "o365"].iloc[0]
    assert json.loads(o365_row["score_data"]) == {"score": 82}


@responses.activate
def test_graphql_errors_raise_incomplete_collection() -> None:
    from posture.exceptions import IncompleteCollection

    responses.add(
        responses.POST,
        _ENDPOINT,
        json={"errors": [{"message": "bad query"}]},
        status=200,
    )

    ccm = CCM("obsidian", {"token": "tok"})

    try:
        ccm.collect("posture_rules")
        assert False, "expected IncompleteCollection"
    except IncompleteCollection:
        pass


@responses.activate
def test_unauthorized_raises_incomplete_collection() -> None:
    from posture.exceptions import IncompleteCollection

    responses.add(
        responses.POST,
        _ENDPOINT,
        json={"error": "unauthorized"},
        status=401,
    )

    ccm = CCM("obsidian", {"token": "bad"})

    try:
        ccm.collect("posture_rules")
        assert False, "expected IncompleteCollection"
    except IncompleteCollection:
        pass
