"""Runtime-agnostic CCM (Continuous Control Monitoring) data collection.

The entire contract: credentials in, DataFrame out.

    from posture import CCM

    ccm = CCM("crowdstrike")
    df = ccm.collect("hosts")
"""

from __future__ import annotations

import logging
from typing import Any

from dotenv import find_dotenv, load_dotenv

from posture.base import Collector
from posture.exceptions import (
    AuthenticationError,
    IncompleteCollection,
    PostureError,
    RateLimitExhausted,
    ResourceUnknown,
    StorageConfigError,
    StorageError,
    StorageWriteError,
)
from posture.storage import Storage, storage_catalog, write_storage

logging.getLogger("posture").addHandler(logging.NullHandler())

logger = logging.getLogger("posture")
load_dotenv(find_dotenv(usecwd=True))
logger.debug("loaded .env via python-dotenv")

__version__ = "0.16.1"

__all__ = [
    "CCM",
    "AuthenticationError",
    "IncompleteCollection",
    "PostureError",
    "RateLimitExhausted",
    "ResourceUnknown",
    "Storage",
    "StorageConfigError",
    "StorageError",
    "StorageWriteError",
    "catalog",
    "storage_catalog",
    "write_storage",
]

_SOURCES: dict[str, type[Collector]] = {}


def _register_sources() -> None:
    if _SOURCES:
        return
    from posture.collectors.appomni import AppOmniCollector
    from posture.collectors.azure_entra import AzureEntraCollector
    from posture.collectors.cloudflare import CloudflareCollector
    from posture.collectors.cortex_cloud import CortexCloudCollector
    from posture.collectors.crowdstrike import CrowdstrikeCollector
    from posture.collectors.crowdstrike_cspm import CrowdstrikeCspmCollector
    from posture.collectors.crowdstrike_identity import CrowdstrikeIdentityCollector
    from posture.collectors.dnsimple import DnsimpleCollector
    from posture.collectors.github import GithubCollector
    from posture.collectors.intune import IntuneCollector
    from posture.collectors.jamf import JamfCollector
    from posture.collectors.kandji import KandjiCollector
    from posture.collectors.knowbe4 import Knowbe4Collector
    from posture.collectors.mde import MdeCollector
    from posture.collectors.okta import OktaCollector
    from posture.collectors.phriendly_phishing import PhriendlyPhishingCollector
    from posture.collectors.qualys import QualysCollector
    from posture.collectors.sailpoint import SailpointCollector
    from posture.collectors.salesforce import SalesforceCollector
    from posture.collectors.sentinelone import SentinelOneCollector
    from posture.collectors.servicenow import ServicenowCollector
    from posture.collectors.snyk import SnykCollector
    from posture.collectors.sonarcloud import SonarcloudCollector
    from posture.collectors.tenableio import TenableioCollector
    from posture.collectors.tenablesc import TenablescCollector
    from posture.collectors.upguard import UpGuardCollector
    from posture.collectors.vanta import VantaCollector
    from posture.collectors.whistic import WhisticCollector
    from posture.collectors.wiz import WizCollector
    from posture.collectors.workspaceone import WorkspaceOneCollector

    _SOURCES["appomni"] = AppOmniCollector
    _SOURCES["azure_entra"] = AzureEntraCollector
    _SOURCES["cloudflare"] = CloudflareCollector
    _SOURCES["cortex_cloud"] = CortexCloudCollector
    _SOURCES["crowdstrike"] = CrowdstrikeCollector
    _SOURCES["crowdstrike_cspm"] = CrowdstrikeCspmCollector
    _SOURCES["crowdstrike_identity"] = CrowdstrikeIdentityCollector
    _SOURCES["dnsimple"] = DnsimpleCollector
    _SOURCES["github"] = GithubCollector
    _SOURCES["intune"] = IntuneCollector
    _SOURCES["jamf"] = JamfCollector
    _SOURCES["kandji"] = KandjiCollector
    _SOURCES["knowbe4"] = Knowbe4Collector
    _SOURCES["mde"] = MdeCollector
    _SOURCES["okta"] = OktaCollector
    _SOURCES["phriendly_phishing"] = PhriendlyPhishingCollector
    _SOURCES["qualys"] = QualysCollector
    _SOURCES["sailpoint"] = SailpointCollector
    _SOURCES["salesforce"] = SalesforceCollector
    _SOURCES["sentinelone"] = SentinelOneCollector
    _SOURCES["servicenow"] = ServicenowCollector
    _SOURCES["snyk"] = SnykCollector
    _SOURCES["sonarcloud"] = SonarcloudCollector
    _SOURCES["tenableio"] = TenableioCollector
    _SOURCES["tenablesc"] = TenablescCollector
    _SOURCES["upguard"] = UpGuardCollector
    _SOURCES["vanta"] = VantaCollector
    _SOURCES["whistic"] = WhisticCollector
    _SOURCES["wiz"] = WizCollector
    _SOURCES["workspaceone"] = WorkspaceOneCollector


def CCM(
    source: str,
    config: dict[str, Any] | None = None,
    *,
    record_limit: int | None = None,
) -> Collector:
    """Construct a collector for ``source``. One instance = one snapshot.

    ``record_limit`` caps raw records per resource — for a quick smoke test
    of a source's extraction, not a full collection run.
    """
    _register_sources()
    try:
        collector_cls = _SOURCES[source]
    except KeyError:
        raise ValueError(
            f"Unknown source '{source}'. Available: {sorted(_SOURCES)}"
        ) from None
    return collector_cls(config, record_limit=record_limit)


def catalog() -> dict[str, Any]:
    """Return what posture has to offer, read straight off the collector classes.

    No instantiation, no credentials, no network calls — just the sources
    registered, the required config each needs (as constructor keys and the
    env vars they fall back to), and each source's resources (including
    which are derived and their declared columns). Code as documentation:
    this is only ever as accurate as the classes it reads, and it stays that
    way for free as collectors change.
    """
    _register_sources()
    sources: dict[str, Any] = {}
    for name, cls in sorted(_SOURCES.items()):
        sources[name] = {
            "display_name": cls.display_name or cls.env_prefix,
            "required_config": {
                key: f"{cls.env_prefix}_{key.upper()}"
                for key, required in cls.config_keys.items()
                if required
            },
            "optional_config": {
                key: f"{cls.env_prefix}_{key.upper()}"
                for key, required in cls.config_keys.items()
                if not required
            },
            "resources": {
                resource: {
                    "derived_from": manifest.get("derived_from"),
                    "columns": list(manifest["columns"]),
                    "column_types": {
                        col: type_ for col, (_, type_) in manifest["columns"].items()
                    },
                }
                for resource, manifest in cls.manifest.items()
            },
        }
    return sources
