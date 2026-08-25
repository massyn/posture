"""Tests for Collector._iter_raw_pages' page-cache key (base.py).

A collector's kwargs are the vendor query dialect and are never restricted
to hashable types by the locked kwargs contract (e.g. a list-valued
`device_ids`/`types`/`products` kwarg is a natural shape) — but the cache
key built from kwargs used to hash them raw via
`tuple(sorted(kwargs.items()))`, which raised `TypeError: unhashable type`
for any collector called with a list (or dict) kwarg value, regardless of
whether that resource was ever actually cached. `_freeze()` converts kwarg
values into an equivalent hashable structure before they reach the cache
key, so any kwargs shape a collector accepts also works with
`collect()`/`collect_page()`.
"""

from __future__ import annotations

from typing import Any, ClassVar

from posture.base import Collector, _freeze


class _DummyCollector(Collector):
    env_prefix = "DUMMY"
    manifest: ClassVar[dict[str, Any]] = {"widgets": {"columns": {"id": ("id", "str")}}}

    def _authenticate(self) -> None:
        pass

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        return [{"id": ",".join(kwargs.get("ids", []))}], None


def test_freeze_converts_nested_unhashables_to_hashable_equivalents() -> None:
    assert _freeze(["a", "b"]) == ("a", "b")
    assert _freeze({"x": [1, 2], "y": {"z": 1}}) == (
        ("x", (1, 2)),
        ("y", (("z", 1),)),
    )
    assert _freeze("scalar") == "scalar"


def test_collect_with_a_list_valued_kwarg_does_not_raise() -> None:
    collector = _DummyCollector({})

    df = collector.collect("widgets", ids=["a", "b", "c"])

    assert list(df["id"]) == ["a,b,c"]
