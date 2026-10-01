import os
from pathlib import Path

import pandas as pd
import pyarrow.parquet as pq
import pytest
import responses

from posture import cli
from posture.exceptions import PostureError
from posture.parse import parse

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


def test_log_parameters_tags_explicit_vs_default(caplog, monkeypatch) -> None:
    monkeypatch.delenv("POSTURE_HISTORY", raising=False)
    args = cli._parse_args(["--include", "macadmins", "--thread", "5"])
    cli._apply_env_defaults(args)
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
    assert "Seconds" in output
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
            "seconds": 0.0,
            "status": "failed: Unknown source 'macadmins'",
        }
    ]


def test_collect_resource_types_columns_from_manifest_not_first_page(
    tmp_path: Path,
) -> None:
    # Page one's `reason` is all-null, which pyarrow alone would type as
    # `null` and then reject page two's string values against.
    manifest = {"columns": {"id": ("id", "int"), "reason": ("reason", "str")}}

    class FakeCCM:
        def column_types(self, resource: str) -> dict[str, str]:
            return {"id": "int", "reason": "str", "_collected_at": "datetime"}

        def collect_page(self, resource: str):
            for raw in ([{"id": 1, "reason": None}], [{"id": 2, "reason": "fixed"}]):
                df = parse(raw, manifest, resource=resource)
                df["_collected_at"] = pd.Timestamp("2026-10-01", tz="UTC")
                yield df

    path = tmp_path / "fake_issues.parquet"
    assert cli._collect_resource(FakeCCM(), "issues", path) == 2

    table = pq.read_table(path)
    assert table.column("reason").to_pylist() == [None, "fixed"]
    assert str(table.schema.field("reason").type) == "string"


def test_use_env_file_replaces_default_dotenv_values(
    tmp_path: Path, monkeypatch
) -> None:
    # PROD_ONLY came from the default .env; SHELL_VAR was set in the shell.
    monkeypatch.setattr(cli.posture, "_DOTENV_KEYS", frozenset({"PROD_ONLY"}))
    monkeypatch.setenv("PROD_ONLY", "prod")
    monkeypatch.setenv("SHELL_VAR", "from-shell")
    # setenv first so monkeypatch records NONPROD_ONLY and removes the value
    # load_dotenv sets once the test ends.
    monkeypatch.setenv("NONPROD_ONLY", "placeholder")
    monkeypatch.delenv("NONPROD_ONLY")
    env_file = tmp_path / ".env.nonprod"
    env_file.write_text("NONPROD_ONLY=nonprod\nSHELL_VAR=from-file\n")

    cli._use_env_file(env_file)

    assert "PROD_ONLY" not in os.environ  # default .env's value doesn't leak
    assert os.environ["NONPROD_ONLY"] == "nonprod"
    assert os.environ["SHELL_VAR"] == "from-shell"  # the shell still wins


def test_main_env_missing_file_exits(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="--env file not found"):
        cli.main(["--env", str(tmp_path / "nope.env")])


def test_output_falls_back_to_posture_output_then_default(monkeypatch) -> None:
    monkeypatch.setenv("POSTURE_OUTPUT", "/data/from-env")
    args = cli._parse_args([])
    cli._apply_env_defaults(args)
    assert args.output == "/data/from-env"

    monkeypatch.delenv("POSTURE_OUTPUT")
    args = cli._parse_args([])
    cli._apply_env_defaults(args)
    assert args.output == "output"


def test_explicit_output_beats_posture_output(monkeypatch, caplog) -> None:
    monkeypatch.setenv("POSTURE_OUTPUT", "/data/from-env")
    argv = ["--output", "/data/explicit"]
    args = cli._parse_args(argv)
    cli._apply_env_defaults(args)
    assert args.output == "/data/explicit"

    with caplog.at_level("INFO", logger="posture.cli"):
        cli._log_parameters(args, argv)
    assert "parameter output = '/data/explicit' (explicit)" in caplog.messages


def test_log_parameters_tags_output_from_environment(monkeypatch, caplog) -> None:
    monkeypatch.setenv("POSTURE_OUTPUT", "/data/from-env")
    args = cli._parse_args([])
    cli._apply_env_defaults(args)

    with caplog.at_level("INFO", logger="posture.cli"):
        cli._log_parameters(args, [])
    assert (
        "parameter output = '/data/from-env' (environment POSTURE_OUTPUT)"
        in caplog.messages
    )


@responses.activate
def test_main_reads_posture_output_from_env_file(tmp_path: Path, monkeypatch) -> None:
    responses.add(responses.GET, _FEED_URL, json=_FEED, status=200)
    out_dir = tmp_path / "nonprod-output"
    env_file = tmp_path / ".env.nonprod"
    env_file.write_text(f"POSTURE_OUTPUT={out_dir.as_posix()}\n")
    # Registered with monkeypatch so the value load_dotenv sets is removed after.
    monkeypatch.setenv("POSTURE_OUTPUT", "placeholder")
    monkeypatch.delenv("POSTURE_OUTPUT")

    exit_code = cli.main(["--include", "macadmins", "--env", str(env_file)])

    assert exit_code == 0
    assert (out_dir / "macadmins_macos_releases.parquet").is_file()


def test_collect_source_records_seconds_per_table(monkeypatch, tmp_path: Path) -> None:
    ticks = iter([100.0, 102.5, 200.0, 201.25])
    monkeypatch.setattr(cli.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(cli, "CCM", lambda source: object())

    def fake_collect(ccm, resource: str, path: Path) -> int:
        if resource == "broken":
            raise PostureError("boom")
        return 7

    monkeypatch.setattr(cli, "_collect_resource", fake_collect)

    results = cli._collect_source(
        "src", {"resources": {"ok_table": {}, "broken": {}}}, tmp_path, history=False
    )

    assert [(r["table"], r["seconds"]) for r in results] == [
        ("src_ok_table", 2.5),
        ("src_broken", 1.25),  # a failed table is still timed
    ]


def test_log_summary_shows_seconds_column(caplog) -> None:
    results = [{"table": "t", "records": 3, "seconds": 12.345, "status": "ok"}]
    with caplog.at_level("INFO", logger="posture.cli"):
        cli._log_summary(results)
    assert "Seconds" in caplog.messages[1]
    assert "12.3" in caplog.messages[3]


@pytest.mark.parametrize(
    ("value", "expected"),
    [("true", True), ("YES", True), ("1", True), ("off", False), ("0", False)],
)
def test_history_falls_back_to_posture_history(
    monkeypatch, value: str, expected: bool
) -> None:
    monkeypatch.setenv("POSTURE_HISTORY", value)
    args = cli._parse_args([])
    cli._apply_env_defaults(args)
    assert args.history is expected


def test_history_defaults_off_without_posture_history(monkeypatch) -> None:
    monkeypatch.delenv("POSTURE_HISTORY", raising=False)
    args = cli._parse_args([])
    cli._apply_env_defaults(args)
    assert args.history is False


def test_no_history_flag_overrides_posture_history(monkeypatch, caplog) -> None:
    monkeypatch.setenv("POSTURE_HISTORY", "true")
    argv = ["--no-history"]
    args = cli._parse_args(argv)
    cli._apply_env_defaults(args)
    assert args.history is False

    with caplog.at_level("INFO", logger="posture.cli"):
        cli._log_parameters(args, argv)
    assert "parameter history = False (explicit)" in caplog.messages


def test_invalid_posture_history_exits(monkeypatch) -> None:
    monkeypatch.setenv("POSTURE_HISTORY", "sometimes")
    args = cli._parse_args([])
    with pytest.raises(
        SystemExit, match="POSTURE_HISTORY='sometimes' is not a boolean"
    ):
        cli._apply_env_defaults(args)


@responses.activate
def test_main_posture_history_writes_dated_file(tmp_path: Path, monkeypatch) -> None:
    responses.add(responses.GET, _FEED_URL, json=_FEED, status=200)
    monkeypatch.setenv("POSTURE_HISTORY", "true")

    exit_code = cli.main(["--include", "macadmins", "--output", str(tmp_path)])

    assert exit_code == 0
    assert list((tmp_path / "macadmins_macos_releases").glob("*.parquet"))
