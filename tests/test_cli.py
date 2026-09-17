from pathlib import Path

import pyarrow.parquet as pq
import pytest
import responses

from posture import cli

_FEED_URL = "https://sofafeed.macadmins.io/v1/macos_data_feed.json"
_FEED = {
    "OSVersions": [
        {
            "OSVersion": "Sequoia 15",
            "Latest": {"ProductVersion": "15.6", "Build": "24G84"},
            "SecurityReleases": [
                {
                    "ProductVersion": "15.6",
                    "ReleaseDate": "2026-07-14T00:00:00Z",
                    "ReleaseType": "OS",
                    "SecurityInfo": "https://support.apple.com/en-us/121101",
                    "UniqueCVEsCount": 1,
                    "DaysSincePreviousRelease": 28,
                    "CVEs": {"CVE-2026-11111": True},
                }
            ],
        }
    ]
}


def test_select_sources_include_bypasses_environment_check(monkeypatch) -> None:
    monkeypatch.delenv("CROWDSTRIKE_CLIENT_ID", raising=False)
    sources = cli._select_sources(["macadmins"])
    assert set(sources) == {"macadmins"}


def test_select_sources_unknown_include_raises_systemexit() -> None:
    with pytest.raises(SystemExit):
        cli._select_sources(["not-a-real-source"])


def test_select_sources_default_uses_environment_filter(monkeypatch) -> None:
    monkeypatch.delenv("ENDOFLIFE_PRODUCTS", raising=False)
    sources = cli._select_sources(None)
    assert "macadmins" not in sources  # no-auth sources excluded by default


def test_output_path_default_vs_history(tmp_path: Path) -> None:
    default_path = cli._output_path(tmp_path, "macadmins_macos_releases", history=False)
    assert default_path == tmp_path / "macadmins_macos_releases.parquet"

    history_path = cli._output_path(tmp_path, "macadmins_macos_releases", history=True)
    assert history_path.parent == tmp_path / "macadmins_macos_releases"
    assert history_path.suffix == ".parquet"


@responses.activate
def test_main_collects_include_source_to_parquet(tmp_path: Path) -> None:
    responses.add(responses.GET, _FEED_URL, json=_FEED, status=200)

    exit_code = cli.main(["--include", "macadmins", "--output", str(tmp_path)])

    assert exit_code == 0
    releases_path = tmp_path / "macadmins_macos_releases.parquet"
    cves_path = tmp_path / "macadmins_macos_cves.parquet"
    assert releases_path.is_file()
    assert cves_path.is_file()

    table = pq.read_table(releases_path)
    assert table.num_rows == 1
    assert table.column("product_version")[0].as_py() == "15.6"


@responses.activate
def test_main_history_writes_dated_file(tmp_path: Path) -> None:
    responses.add(responses.GET, _FEED_URL, json=_FEED, status=200)

    exit_code = cli.main(
        ["--include", "macadmins", "--output", str(tmp_path), "--history"]
    )

    assert exit_code == 0
    dated_files = list((tmp_path / "macadmins_macos_releases").glob("*.parquet"))
    assert len(dated_files) == 1


def test_main_unknown_include_source_exits(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        cli.main(["--include", "not-a-real-source", "--output", str(tmp_path)])


@responses.activate
def test_main_debug_sets_root_logger_to_debug(tmp_path: Path) -> None:
    import logging

    responses.add(responses.GET, _FEED_URL, json=_FEED, status=200)

    exit_code = cli.main(
        ["--include", "macadmins", "--output", str(tmp_path), "--debug"]
    )

    assert exit_code == 0
    assert logging.getLogger().level == logging.DEBUG


def test_thread_default_is_three() -> None:
    args = cli._parse_args(["--include", "macadmins"])
    assert args.thread == 3


def test_log_parameters_tags_explicit_vs_default(caplog) -> None:
    args = cli._parse_args(["--include", "macadmins", "--thread", "5"])
    argv = ["--include", "macadmins", "--thread", "5"]

    with caplog.at_level("INFO", logger="posture.cli"):
        cli._log_parameters(args, argv)

    messages = "\n".join(caplog.messages)
    assert "thread = 5 (explicit)" in messages
    assert "history = False (default)" in messages


@responses.activate
def test_main_runs_with_multiple_threads(tmp_path: Path) -> None:
    responses.add(responses.GET, _FEED_URL, json=_FEED, status=200)

    exit_code = cli.main(
        ["--include", "macadmins", "--output", str(tmp_path), "--thread", "2"]
    )

    assert exit_code == 0
    assert (tmp_path / "macadmins_macos_releases.parquet").is_file()


@responses.activate
def test_main_prints_summary_table(tmp_path: Path, capsys) -> None:
    # main() calls logging.basicConfig(force=True), which strips any handler
    # pytest's caplog fixture attached — assert on the actual stderr output
    # (basicConfig's default stream) instead.
    responses.add(responses.GET, _FEED_URL, json=_FEED, status=200)

    exit_code = cli.main(["--include", "macadmins", "--output", str(tmp_path)])

    assert exit_code == 0
    output = capsys.readouterr().err
    assert "Summary:" in output
    assert "macadmins_macos_releases" in output
    assert "macadmins_macos_cves" in output
    assert "ok" in output


def test_collect_source_reports_failed_table_in_summary(
    monkeypatch, tmp_path: Path
) -> None:
    from posture.exceptions import SourceUnknown

    def _raise_source_unknown(*args, **kwargs):
        raise SourceUnknown("Unknown source 'macadmins'")

    monkeypatch.setattr(cli, "CCM", _raise_source_unknown)

    results = cli._collect_source(
        "macadmins", {"resources": {}}, tmp_path, history=False
    )

    assert results == [
        {
            "table": "macadmins",
            "records": 0,
            "status": "failed: Unknown source 'macadmins'",
        }
    ]
