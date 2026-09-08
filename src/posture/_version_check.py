"""Best-effort check for a newer posture release on PyPI.

Purely informational. Every failure mode — offline, timeout, a proxy
returning HTML, an unexpected JSON shape — is swallowed and treated as "no
newer version known". This module never raises and never blocks a caller
for longer than ``_TIMEOUT_SECONDS``.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import requests

logger = logging.getLogger("posture")

_PYPI_URL = "https://pypi.org/pypi/posture/json"
_TIMEOUT_SECONDS = 2.0
_OPT_OUT_ENV = "POSTURE_VERSION_CHECK"
_OPT_OUT_VALUES = {"0", "false", "no", "off"}

_checked = False


def _parse(version: str) -> tuple[int, ...]:
    """Leading numeric release components of ``version`` as an int tuple.

    ``"1.2.3"`` -> ``(1, 2, 3)``; parsing stops at the first non-numeric
    component (``"1.2.0rc1"`` -> ``(1, 2)``), which is enough to compare two
    normal releases without pulling in ``packaging``.
    """
    parts: list[int] = []
    for chunk in version.split("."):
        if not chunk.isdigit():
            break
        parts.append(int(chunk))
    return tuple(parts)


def latest_version() -> str | None:
    """Version string of the newest posture release on PyPI, or ``None``."""
    try:
        response = requests.get(_PYPI_URL, timeout=_TIMEOUT_SECONDS)
        response.raise_for_status()
        payload: dict[str, Any] = response.json()
        version = payload["info"]["version"]
        return str(version) if version else None
    except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
        logger.debug("PyPI version check skipped: %s", exc)
        return None


def check_for_update(*, force: bool = False) -> str | None:
    """Log a warning if PyPI has a newer posture than the one running.

    Runs at most once per process and is silently skipped when
    ``POSTURE_VERSION_CHECK`` is set to a falsey value. Returns the newer
    version string when one is found, otherwise ``None``. ``force=True``
    bypasses both the once-per-process guard and the opt-out.
    """
    global _checked

    if not force:
        if _checked:
            return None
        if os.environ.get(_OPT_OUT_ENV, "").strip().lower() in _OPT_OUT_VALUES:
            return None
    _checked = True

    from posture import __version__

    latest = latest_version()
    if latest is None:
        return None
    if _parse(latest) > _parse(__version__):
        logger.warning(
            "posture %s is installed but %s is available on PyPI - "
            "upgrade with 'pip install --upgrade posture'",
            __version__,
            latest,
        )
        return latest
    return None
