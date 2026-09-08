"""Shared pytest fixtures."""

from __future__ import annotations

import pytest

from posture import _version_check


@pytest.fixture(autouse=True)
def _disable_pypi_version_check(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the suite hermetic: never let ``CCM()`` reach out to PyPI.

    ``check_for_update`` is exercised directly in ``test_version_check.py``
    with a mocked transport; everywhere else it must be a no-op.
    """
    monkeypatch.setenv("POSTURE_VERSION_CHECK", "0")
    monkeypatch.setattr(_version_check, "_checked", False)
