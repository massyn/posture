import responses

from posture import CCM


@responses.activate
def test_managed_devices_follows_odata_next_link() -> None:
    responses.add(
        responses.POST,
        "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token",
        json={"access_token": "tok"},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices",
        json={
            "value": [{"id": "dev-1"}],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$skiptoken=abc",
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$skiptoken=abc",
        json={"value": [{"id": "dev-2"}]},
        status=200,
    )

    ccm = CCM(
        "intune",
        {"tenant_id": "tenant-1", "client_id": "id", "client_secret": "secret"},
    )
    df = ccm.collect("managed_devices")

    assert list(df["device_id"]) == ["dev-1", "dev-2"]
    assert ccm.report("managed_devices")["pages"] == 2


@responses.activate
def test_managed_device_detail_batches_ids_from_managed_devices() -> None:
    responses.add(
        responses.POST,
        "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token",
        json={"access_token": "tok"},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices",
        json={"value": [{"id": "dev-1"}]},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://graph.microsoft.com/beta/deviceManagement/managedDevices/dev-1",
        json={
            "id": "dev-1",
            "deviceName": "LAPTOP-1",
            "isEncrypted": True,
            "complianceState": "compliant",
            "deviceGuardVirtualizationBasedSecurityState": "running",
            "deviceGuardLocalSystemAuthorityCredentialGuardState": "running",
            "windowsActiveMalwareCount": 0,
            "lastSyncDateTime": "2026-07-20T00:00:00Z",
            "userPrincipalName": "user@example.com",
        },
        status=200,
    )

    ccm = CCM(
        "intune",
        {"tenant_id": "tenant-1", "client_id": "id", "client_secret": "secret"},
    )
    df = ccm.collect("managed_device_detail")

    assert len(df) == 1
    assert df.loc[0, "device_name"] == "LAPTOP-1"
    assert bool(df.loc[0, "is_encrypted"]) is True
    assert df.loc[0, "compliance_state"] == "compliant"
    assert df.loc[0, "device_guard_vbs_state"] == "running"
    assert df.loc[0, "device_guard_credential_guard_state"] == "running"
    assert df.loc[0, "windows_active_malware_count"] == 0
    assert df.loc[0, "user_principal_name"] == "user@example.com"


@responses.activate
def test_attack_simulation_users_drains_pagination_per_simulation() -> None:
    responses.add(
        responses.POST,
        "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token",
        json={"access_token": "tok"},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://graph.microsoft.com/v1.0/security/attackSimulation/simulations",
        json={"value": [{"id": "sim-1"}]},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://graph.microsoft.com/v1.0/security/attackSimulation/simulations/sim-1/report/simulationUsers",
        json={
            "value": [{"simulationUser": {"userId": "user-1"}}],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/security/attackSimulation/simulations/sim-1/report/simulationUsers?$skiptoken=abc",
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "https://graph.microsoft.com/v1.0/security/attackSimulation/simulations/sim-1/report/simulationUsers?$skiptoken=abc",
        json={"value": [{"simulationUser": {"userId": "user-2"}}]},
        status=200,
    )

    ccm = CCM(
        "intune",
        {"tenant_id": "tenant-1", "client_id": "id", "client_secret": "secret"},
    )
    df = ccm.collect("attack_simulation_users")

    assert len(df) == 2
    assert list(df["user_id"]) == ["user-1", "user-2"]
    assert list(df["simulation_id"]) == ["sim-1", "sim-1"]
