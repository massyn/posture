import logging

import responses

from posture import CCM

CLIENT_SECRET = "s3cr3t-do-not-leak"
ACCESS_TOKEN = "totally-secret-bearer-token"


@responses.activate
def test_secrets_never_appear_in_logs_at_debug(caplog) -> None:
    responses.add(
        responses.POST,
        "https://api.crowdstrike.com/oauth2/token",
        json={"access_token": ACCESS_TOKEN, "expires_in": 1800},
        headers={"X-Cs-Region": "us-1"},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.crowdstrike.com/devices/queries/devices/v1",
        json={
            "resources": ["dev-1"],
            "meta": {"pagination": {"total": 1, "offset": 1}},
        },
        status=200,
    )
    responses.add(
        responses.POST,
        "https://api.crowdstrike.com/devices/entities/devices/v2",
        json={
            "resources": [
                {
                    "cid": "cid-1",
                    "device_id": "dev-1",
                    "hostname": "host-1",
                    "last_seen": "2026-07-01T00:00:00Z",
                    "status": "normal",
                }
            ]
        },
        status=200,
    )

    ccm = CCM(
        "crowdstrike", {"client_id": "client-abc", "client_secret": CLIENT_SECRET}
    )

    with caplog.at_level(logging.DEBUG, logger="posture"):
        df = ccm.collect("hosts")

    assert len(df) == 1

    log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert CLIENT_SECRET not in log_text
    assert ACCESS_TOKEN not in log_text

    repr_text = repr(ccm)
    assert CLIENT_SECRET not in repr_text
    assert ACCESS_TOKEN not in repr_text
