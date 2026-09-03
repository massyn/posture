import pytest

from posture import catalog, runnable_sources


def test_catalog_lists_all_registered_sources() -> None:
    result = catalog()

    assert set(result) == {
        "appomni",
        "azure_entra",
        "cloudflare",
        "cortex_cloud",
        "crowdstrike",
        "crowdstrike_cspm",
        "crowdstrike_identity",
        "defender_for_cloud",
        "dnsimple",
        "drata",
        "duo",
        "endoflife",
        "gcp_security_command_center",
        "github",
        "google_workspace",
        "healthchecks",
        "intune",
        "jamf",
        "jira",
        "kandji",
        "knowbe4",
        "mde",
        "miro",
        "nullify",
        "obsidian",
        "okta",
        "phriendly_phishing",
        "plerion",
        "precise",
        "qualys",
        "rapid7_insightvm",
        "runzero",
        "sailpoint",
        "salesforce",
        "securityscorecard",
        "select_star",
        "sentinelone",
        "servicenow",
        "slack",
        "snyk",
        "sonarcloud",
        "teams",
        "tenableio",
        "tenablesc",
        "upguard",
        "uptimerobot",
        "vanta",
        "whistic",
        "wiz",
        "workspaceone",
    }


def test_catalog_reports_required_config_as_constructor_key_to_env_var() -> None:
    result = catalog()

    assert result["crowdstrike"]["required_config"] == {
        "client_id": "CROWDSTRIKE_CLIENT_ID",
        "client_secret": "CROWDSTRIKE_CLIENT_SECRET",
    }
    assert result["knowbe4"]["required_config"] == {
        "token": "KNOWBE4_TOKEN",
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


def test_catalog_reports_display_name() -> None:
    result = catalog()

    # Explicit display_name set on the collector.
    assert result["mde"]["display_name"] == "Microsoft Defender for Endpoint"
    assert result["crowdstrike"]["display_name"] == "CrowdStrike"


def test_catalog_requires_no_credentials_or_network() -> None:
    # No CCM(...) call, no env vars set — catalog() must never instantiate
    # a collector or touch the network.
    result = catalog()
    assert result["knowbe4"]["required_config"]["token"] == "KNOWBE4_TOKEN"


def test_runnable_sources_excludes_source_missing_env_vars(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("KNOWBE4_TOKEN", raising=False)

    assert "knowbe4" not in runnable_sources()


def test_runnable_sources_includes_source_with_all_env_vars_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KNOWBE4_TOKEN", "dummy")

    assert "knowbe4" in runnable_sources()


def test_runnable_sources_requires_every_required_env_var(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CROWDSTRIKE_CLIENT_ID", "dummy")
    monkeypatch.delenv("CROWDSTRIKE_CLIENT_SECRET", raising=False)

    assert "crowdstrike" not in runnable_sources()
