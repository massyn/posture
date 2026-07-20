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
)

logging.getLogger("posture").addHandler(logging.NullHandler())

logger = logging.getLogger("posture")
load_dotenv(find_dotenv(usecwd=False))
logger.debug("loaded .env via python-dotenv")

__version__ = "0.3.1"

__all__ = [
    "CCM",
    "catalog",
    "AuthenticationError",
    "IncompleteCollection",
    "PostureError",
    "RateLimitExhausted",
    "ResourceUnknown",
]

_SOURCES: dict[str, type[Collector]] = {}


def _register_sources() -> None:
    if _SOURCES:
        return
    from posture.collectors.azure_entra import AzureEntraCollector
    from posture.collectors.crowdstrike import CrowdstrikeCollector
    from posture.collectors.intune import IntuneCollector
    from posture.collectors.jamf import JamfCollector
    from posture.collectors.knowbe4 import Knowbe4Collector
    from posture.collectors.mde import MdeCollector
    from posture.collectors.okta import OktaCollector
    from posture.collectors.salesforce import SalesforceCollector
    from posture.collectors.tenableio import TenableioCollector
    from posture.collectors.upguard import UpGuardCollector
    from posture.collectors.workspaceone import WorkspaceOneCollector

    _SOURCES["azure_entra"] = AzureEntraCollector
    _SOURCES["crowdstrike"] = CrowdstrikeCollector
    _SOURCES["intune"] = IntuneCollector
    _SOURCES["jamf"] = JamfCollector
    _SOURCES["knowbe4"] = Knowbe4Collector
    _SOURCES["mde"] = MdeCollector
    _SOURCES["okta"] = OktaCollector
    _SOURCES["salesforce"] = SalesforceCollector
    _SOURCES["tenableio"] = TenableioCollector
    _SOURCES["upguard"] = UpGuardCollector
    _SOURCES["workspaceone"] = WorkspaceOneCollector


def CCM(source: str, config: dict[str, Any] | None = None) -> Collector:
    """Construct a collector for ``source``. One instance = one snapshot."""
    _register_sources()
    try:
        collector_cls = _SOURCES[source]
    except KeyError:
        raise ValueError(
            f"Unknown source '{source}'. Available: {sorted(_SOURCES)}"
        ) from None
    return collector_cls(config)


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
            "required_config": {
                key: f"{cls.env_prefix}_{key.upper()}"
                for key in cls.required_config_keys
            },
            "resources": {
                resource: {
                    "derived_from": manifest.get("derived_from"),
                    "columns": list(manifest["columns"]),
                }
                for resource, manifest in cls.manifest.items()
            },
        }
    return sources
