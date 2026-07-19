from posture import catalog


def test_catalog_lists_all_registered_sources() -> None:
    result = catalog()

    assert set(result) == {
        "azure_entra",
        "crowdstrike",
        "intune",
        "jamf",
        "knowbe4",
        "mde",
        "okta",
        "salesforce",
        "tenableio",
        "upguard",
        "workspaceone",
    }


def test_catalog_reports_required_config_as_constructor_key_to_env_var() -> None:
    result = catalog()

    assert result["crowdstrike"]["required_config"] == {
        "client_id": "CROWDSTRIKE_CLIENT_ID",
        "client_secret": "CROWDSTRIKE_CLIENT_SECRET",
    }
    assert result["knowbe4"]["required_config"] == {
        "api_token": "KNOWBE4_API_TOKEN",
    }
    assert result["tenableio"]["required_config"] == {
        "access_key": "TENABLEIO_ACCESS_KEY",
        "secret_key": "TENABLEIO_SECRET_KEY",
    }


def test_catalog_lists_resources_with_derived_and_columns() -> None:
    result = catalog()

    crowdstrike_resources = result["crowdstrike"]["resources"]
    assert crowdstrike_resources["hosts"]["derived_from"] is None
    assert "device_id" in crowdstrike_resources["hosts"]["columns"]
    assert (
        crowdstrike_resources["vulnerability_remediations"]["derived_from"]
        == "vulnerabilities"
    )

    assert result["tenableio"]["resources"]["assets"]["columns"] == [
        "asset_id",
        "hostname",
        "fqdn",
        "ipv4",
        "ipv6",
        "mac_address",
        "operating_system",
        "network_name",
        "has_agent",
        "agent_uuid",
        "first_seen",
        "last_seen",
        "sources",
    ]


def test_catalog_requires_no_credentials_or_network() -> None:
    # No CCM(...) call, no env vars set — catalog() must never instantiate
    # a collector or touch the network.
    result = catalog()
    assert result["knowbe4"]["required_config"]["api_token"] == "KNOWBE4_API_TOKEN"
