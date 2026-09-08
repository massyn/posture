import logging

import pytest
import requests
import responses

from posture import _version_check
from posture._version_check import _parse, check_for_update

_PYPI_URL = "https://pypi.org/pypi/posture/json"


@pytest.fixture(autouse=True)
def _enable_version_check(monkeypatch: pytest.MonkeyPatch) -> None:
    # The suite-wide conftest fixture disables the check; re-enable it here
    # and start every test from an unchecked process state.
    monkeypatch.delenv("POSTURE_VERSION_CHECK", raising=False)
    monkeypatch.setattr(_version_check, "_checked", False)


def test_parse_reads_leading_numeric_components() -> None:
    assert _parse("1.2.3") == (1, 2, 3)
    assert _parse("1.10.0") == (1, 10, 0)
    assert _parse("2.0.0rc1") == (2, 0)  # parsing stops at the first non-numeric part
    assert _parse("") == ()


@responses.activate
def test_warns_when_pypi_has_newer_release(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr("posture.__version__", "1.1.1")
    responses.add(responses.GET, _PYPI_URL, json={"info": {"version": "1.2.0"}})

    with caplog.at_level(logging.WARNING, logger="posture"):
        result = check_for_update()

    assert result == "1.2.0"
    assert "1.2.0 is available on PyPI" in caplog.text


@responses.activate
def test_silent_when_running_latest(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr("posture.__version__", "9.9.9")
    responses.add(responses.GET, _PYPI_URL, json={"info": {"version": "1.2.0"}})

    with caplog.at_level(logging.WARNING, logger="posture"):
        assert check_for_update() is None
    assert caplog.text == ""


@responses.activate
def test_network_failure_is_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("posture.__version__", "1.1.1")
    responses.add(
        responses.GET, _PYPI_URL, body=requests.exceptions.ConnectionError("boom")
    )

    assert check_for_update() is None


@responses.activate
def test_opt_out_skips_http_call(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POSTURE_VERSION_CHECK", "0")
    monkeypatch.setattr("posture.__version__", "1.1.1")
    responses.add(responses.GET, _PYPI_URL, json={"info": {"version": "1.2.0"}})

    assert check_for_update() is None
    assert len(responses.calls) == 0


@responses.activate
def test_checks_only_once_per_process(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("posture.__version__", "1.1.1")
    responses.add(responses.GET, _PYPI_URL, json={"info": {"version": "1.2.0"}})

    check_for_update()
    check_for_update()

    assert len(responses.calls) == 1


@responses.activate
def test_force_bypasses_guard_and_opt_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POSTURE_VERSION_CHECK", "0")
    monkeypatch.setattr(_version_check, "_checked", True)
    monkeypatch.setattr("posture.__version__", "1.1.1")
    responses.add(responses.GET, _PYPI_URL, json={"info": {"version": "1.2.0"}})

    assert check_for_update(force=True) == "1.2.0"
