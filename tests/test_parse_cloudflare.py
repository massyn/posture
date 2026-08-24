import json
from pathlib import Path

import pandas as pd

from posture.collectors.cloudflare import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "cloudflare"

ZONES_MANIFEST = MANIFEST["zones"]
DNS_RECORDS_MANIFEST = MANIFEST["dns_records"]
CDN_PROTECTED_DOMAINS_MANIFEST = MANIFEST["cdn_protected_domains"]
WORKERS_ROUTES_MANIFEST = MANIFEST["workers_routes"]
PAGES_PROJECTS_MANIFEST = MANIFEST["pages_projects"]
WORKERS_SCRIPTS_MANIFEST = MANIFEST["workers_scripts"]


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_zones_page() -> None:
    df = parse(_load("zones_page.json"), ZONES_MANIFEST, resource="zones")

    assert len(df) == 2
    assert df.loc[0, "name"] == "example.com"
    assert df.loc[0, "status"] == "active"
    assert bool(df.loc[0, "paused"]) is False
    assert df.loc[0, "account_id"] == "acct-1"
    assert df.loc[0, "plan_name"] == "Free Website"
    assert df["created_on"].dtype == "datetime64[us, UTC]"
    assert pd.isna(df.loc[1, "account_id"])  # no account relationship on this zone


def test_dns_records_page() -> None:
    df = parse(
        _load("dns_records_page.json"), DNS_RECORDS_MANIFEST, resource="dns_records"
    )

    assert len(df) == 2
    assert df.loc[0, "zone_id"] == "zone-1"
    assert df.loc[0, "zone_name"] == "example.com"
    assert df.loc[0, "type"] == "A"
    assert bool(df.loc[0, "proxied"]) is True
    assert bool(df.loc[1, "proxied"]) is False
    assert pd.isna(df.loc[1, "comment"])  # absent in fixture


def test_cdn_protected_domains_page() -> None:
    df = parse(
        _load("cdn_protected_domains_page.json"),
        CDN_PROTECTED_DOMAINS_MANIFEST,
        resource="cdn_protected_domains",
    )

    assert len(df) == 1
    assert df.loc[0, "name"] == "www.example.com"
    assert bool(df.loc[0, "proxied"]) is True


def test_workers_routes_page() -> None:
    df = parse(
        _load("workers_routes_page.json"),
        WORKERS_ROUTES_MANIFEST,
        resource="workers_routes",
    )

    assert len(df) == 1
    assert df.loc[0, "zone_id"] == "zone-1"
    assert df.loc[0, "zone_name"] == "example.com"
    assert df.loc[0, "pattern"] == "example.com/api/*"
    assert df.loc[0, "script"] == "api-worker"


def test_pages_projects_page() -> None:
    df = parse(
        _load("pages_projects_page.json"),
        PAGES_PROJECTS_MANIFEST,
        resource="pages_projects",
    )

    assert len(df) == 1
    assert df.loc[0, "account_id"] == "acct-1"
    assert df.loc[0, "name"] == "marketing-site"
    assert df.loc[0, "domains"] == '["www.example.com"]'
    assert df.loc[0, "source_config_repo_name"] == "marketing-site"
    assert df.loc[0, "latest_deployment_environment"] == "production"


def test_workers_scripts_page() -> None:
    df = parse(
        _load("workers_scripts_page.json"),
        WORKERS_SCRIPTS_MANIFEST,
        resource="workers_scripts",
    )

    assert len(df) == 1
    assert df.loc[0, "account_id"] == "acct-1"
    assert df.loc[0, "id"] == "api-worker"
    assert bool(df.loc[0, "logpush"]) is False
    assert df["created_on"].dtype == "datetime64[us, UTC]"
