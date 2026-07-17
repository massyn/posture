"""Runtime-agnostic CCM (Continuous Control Monitoring) data collection.

The entire contract: credentials in, DataFrame out.

    from posture import CCM

    ccm = CCM("crowdstrike")
    df = ccm.collect("hosts")
"""

from __future__ import annotations

import logging
from typing import Any

from dotenv import load_dotenv

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
load_dotenv()
logger.debug("loaded .env via python-dotenv")

__version__ = "0.0.3"

__all__ = [
    "CCM",
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
    from posture.collectors.crowdstrike import CrowdstrikeCollector
    from posture.collectors.intune import IntuneCollector
    from posture.collectors.jamf import JamfCollector
    from posture.collectors.mde import MdeCollector
    from posture.collectors.okta import OktaCollector
    from posture.collectors.upguard import UpGuardCollector
    from posture.collectors.workspaceone import WorkspaceOneCollector

    _SOURCES["crowdstrike"] = CrowdstrikeCollector
    _SOURCES["intune"] = IntuneCollector
    _SOURCES["jamf"] = JamfCollector
    _SOURCES["mde"] = MdeCollector
    _SOURCES["okta"] = OktaCollector
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
