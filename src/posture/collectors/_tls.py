"""Shared TLS-verification config for self-hosted collectors.

Internal to collectors whose server is commonly self-hosted behind a
self-signed or internal-CA certificate (``bigfix``, ``cyberark``). Kept out of
``base.py`` deliberately — certificate handling stays a per-collector opt-in,
not a base-class concern — and promoted out of ``bigfix.py`` into this shared
module only because a second collector (CyberArk) demonstrably needed the
same logic, per the anti-overfitting rule in CLAUDE.md.

A collector lists ``ca_bundle`` and ``insecure`` as optional ``config_keys``
and passes the result of ``resolve_verify`` as ``verify=`` on every request.
Per request, not as ``session.verify``: requests lets a
``REQUESTS_CA_BUNDLE``/``CURL_CA_BUNDLE`` env var silently override
``session.verify``, but never an explicit per-request ``verify=``.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("posture.collectors.tls")

_TRUE_STRINGS = frozenset({"true", "1", "yes"})
_FALSE_STRINGS = frozenset({"false", "0", "no", ""})


def resolve_verify(config: dict[str, Any], env_prefix: str) -> bool | str:
    """Return the ``verify=`` value for ``config``'s ``ca_bundle``/``insecure``.

    ``ca_bundle`` (path to a PEM CA bundle) and ``insecure`` (bool, or
    true/false as a string from the environment) are mutually exclusive; with
    neither set, certificates are verified against the default trust store.
    Raises ``ValueError`` at construction time for a bad value, a missing
    bundle file, or both keys set.
    """
    insecure = config.get("insecure", False)
    if isinstance(insecure, str):
        lowered = insecure.strip().lower()
        if lowered not in _TRUE_STRINGS | _FALSE_STRINGS:
            raise ValueError(
                f"Invalid 'insecure' value {insecure!r}: expected true or false "
                f"(env var {env_prefix}_INSECURE)"
            )
        insecure = lowered in _TRUE_STRINGS
    ca_bundle = config.get("ca_bundle")

    if insecure and ca_bundle:
        raise ValueError(
            "Config 'insecure' and 'ca_bundle' are mutually exclusive: set one "
            f"or the other (env vars {env_prefix}_INSECURE / {env_prefix}_CA_BUNDLE)"
        )
    if ca_bundle:
        if not Path(ca_bundle).is_file():
            raise ValueError(
                f"Config 'ca_bundle' file not found: {ca_bundle} "
                f"(env var {env_prefix}_CA_BUNDLE)"
            )
        return str(ca_bundle)
    if insecure:
        logger.warning(
            "TLS certificate verification disabled",
            extra={"source": env_prefix.lower()},
        )
        return False
    return True
