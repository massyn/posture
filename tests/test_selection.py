import pytest

from posture._selection import select_tables, split_list


def test_split_list_accepts_commas_and_whitespace() -> None:
    assert split_list("X", " a, b.c  d,,") == ["a", "b.c", "d"]


def test_include_bypasses_environment_check(monkeypatch) -> None:
    monkeypatch.delenv("CROWDSTRIKE_CLIENT_ID", raising=False)
    assert select_tables(["macadmins"], None) == {
        "macadmins": ["macos_releases", "macos_cves"]
    }


def test_default_uses_environment_filter(monkeypatch) -> None:
    monkeypatch.delenv("ENDOFLIFE_PRODUCTS", raising=False)
    assert "macadmins" not in select_tables(None, None)  # no-auth: not by default


def test_include_resource_selects_only_that_resource() -> None:
    assert select_tables(["macadmins.macos_cves"], None) == {
        "macadmins": ["macos_cves"]
    }


def test_include_whole_source_wins_over_resource_entry() -> None:
    tables = select_tables(["macadmins.macos_cves", "macadmins"], None)
    assert tables == {"macadmins": ["macos_releases", "macos_cves"]}


def test_exclude_resource_drops_only_that_resource() -> None:
    tables = select_tables(["macadmins"], ["macadmins.macos_releases"])
    assert tables == {"macadmins": ["macos_cves"]}


def test_exclude_source_drops_it_from_include() -> None:
    assert select_tables(["macadmins", "endoflife"], ["macadmins"]) == {
        "endoflife": ["products", "cycles"]
    }


def test_source_with_every_resource_excluded_is_dropped() -> None:
    exclude = ["macadmins.macos_releases", "macadmins.macos_cves"]
    assert select_tables(["macadmins"], exclude) == {}


def test_exclude_applies_to_environment_default(monkeypatch) -> None:
    monkeypatch.setenv("HTTP_HOSTS", "example.com")
    assert "http" in select_tables(None, None)
    assert "http" not in select_tables(None, ["http"])


@pytest.mark.parametrize(
    ("include", "exclude"),
    [
        (["not-a-real-source"], None),
        (["macadmins.not_a_resource"], None),
        (["macadmins"], ["nope"]),
    ],
)
def test_unknown_entry_exits(include, exclude) -> None:
    with pytest.raises(SystemExit, match="Use <source> or <source>.<resource>"):
        select_tables(include, exclude)
