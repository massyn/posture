"""Base-class URL/endpoint normalization, applied via `url_config_keys`.

Operators supply a base URL/endpoint with or without a scheme, depending on
the vendor's own docs (e.g. Tenable.sc's on-prem host, DNSimple's sandbox
endpoint, Wiz's tenant GraphQL endpoint, SailPoint's tenant base URL) — this
must consistently normalize to https:// with no trailing slash regardless.
"""

import pytest

from posture.collectors.dnsimple import DnsimpleCollector
from posture.collectors.sailpoint import SailpointCollector
from posture.collectors.tenablesc import TenablescCollector
from posture.collectors.wiz import WizCollector


@pytest.mark.parametrize(
    "given,expected",
    [
        ("host.example.com", "https://host.example.com"),
        ("https://host.example.com", "https://host.example.com"),
        ("https://host.example.com/", "https://host.example.com"),
        ("http://host.example.com", "http://host.example.com"),
    ],
)
def test_sailpoint_base_url_normalized(given, expected):
    c = SailpointCollector({"base_url": given, "client_id": "x", "client_secret": "y"})
    assert c._config["base_url"] == expected


@pytest.mark.parametrize(
    "given,expected",
    [
        ("sc.example.com", "https://sc.example.com"),
        ("https://sc.example.com/", "https://sc.example.com"),
    ],
)
def test_tenablesc_endpoint_normalized(given, expected):
    c = TenablescCollector({"endpoint": given, "access_key": "x", "secret_key": "y"})
    assert c._config["endpoint"] == expected


@pytest.mark.parametrize(
    "given,expected",
    [
        ("api.eu1.app.wiz.io/graphql", "https://api.eu1.app.wiz.io/graphql"),
        ("https://api.eu1.app.wiz.io/graphql/", "https://api.eu1.app.wiz.io/graphql"),
    ],
)
def test_wiz_api_endpoint_normalized(given, expected):
    c = WizCollector({"client_id": "x", "client_secret": "y", "api_endpoint": given})
    assert c._config["api_endpoint"] == expected


def test_dnsimple_endpoint_normalized_when_overridden():
    c = DnsimpleCollector({"token": "x", "endpoint": "sandbox.dnsimple.com/v2"})
    assert c._config["endpoint"] == "https://sandbox.dnsimple.com/v2"


def test_dnsimple_default_endpoint_still_normalized():
    c = DnsimpleCollector({"token": "x"})
    assert c._config["endpoint"] == "https://api.dnsimple.com/v2"
