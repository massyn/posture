"""Tests for Collector._resumable_fanout (base.py).

Covers todo #351 / Citadel entry #223: a fan-out retried by
_request_with_retry must resume from where it left off, not re-fetch
already-completed ids from scratch.
"""

from __future__ import annotations

import threading
from typing import Any

import pytest

from posture.base import Collector


class _DummyCollector(Collector):
    env_prefix = "DUMMY"
    manifest = {"widgets": {"columns": {}}}

    def _authenticate(self) -> None:
        pass

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        raise NotImplementedError


def _collector() -> _DummyCollector:
    return _DummyCollector({})


def test_resumable_fanout_resumes_after_mid_run_failure() -> None:
    """N of M ids complete, then a worker raises; a second call with the
    same ids only re-fetches the M-N that hadn't completed, and the final
    result set has all M records — total underlying calls == M, not N + M.
    """
    collector = _collector()
    call_count = 0
    call_lock = threading.Lock()
    fail_after = 3

    def fetch_one(item_id: str) -> dict[str, Any]:
        nonlocal call_count
        with call_lock:
            call_count += 1
            n = call_count
        if n == fail_after:
            raise RuntimeError("simulated transient failure")
        return {"id": item_id}

    ids = [f"id-{i}" for i in range(10)]

    with pytest.raises(RuntimeError):
        collector._resumable_fanout("widgets", ids, fetch_one, max_workers=1)

    # Progress from the failed attempt survived.
    assert "widgets" in collector._fanout_progress
    completed_before_failure = len(collector._fanout_progress["widgets"])
    assert 0 < completed_before_failure < len(ids)

    calls_before_retry = call_count

    def fetch_one_no_fail(item_id: str) -> dict[str, Any]:
        nonlocal call_count
        with call_lock:
            call_count += 1
        return {"id": item_id}

    records = collector._resumable_fanout(
        "widgets", ids, fetch_one_no_fail, max_workers=1
    )

    assert sorted(r["id"] for r in records) == sorted(ids)
    # Total calls across both attempts == len(ids), not len(ids) + completed_before_failure.
    assert call_count == len(ids) + (calls_before_retry - completed_before_failure)


def test_resumable_fanout_clears_progress_on_success() -> None:
    collector = _collector()

    def fetch_one(item_id: str) -> dict[str, Any]:
        return {"id": item_id}

    records = collector._resumable_fanout(
        "widgets", ["a", "b"], fetch_one, max_workers=2
    )

    assert sorted(r["id"] for r in records) == ["a", "b"]
    assert "widgets" not in collector._fanout_progress


def test_resumable_fanout_none_result_is_a_completed_result() -> None:
    """A None result (e.g. a 404 the caller treats as confirmed-missing) is
    stored as done and not re-fetched on a subsequent call for the same ids.
    """
    collector = _collector()
    calls: list[str] = []

    def fetch_one(item_id: str) -> dict[str, Any] | None:
        calls.append(item_id)
        return None if item_id == "missing" else {"id": item_id}

    ids = ["a", "missing", "b"]
    records = collector._resumable_fanout("widgets", ids, fetch_one, max_workers=2)

    assert sorted(r["id"] for r in records) == ["a", "b"]
    assert sorted(calls) == sorted(ids)
    assert "widgets" not in collector._fanout_progress


def test_resumable_fanout_flattens_list_results() -> None:
    collector = _collector()

    def fetch_one(item_id: str) -> list[dict[str, Any]]:
        return [{"id": item_id, "n": 1}, {"id": item_id, "n": 2}]

    records = collector._resumable_fanout(
        "widgets", ["a", "b"], fetch_one, max_workers=2
    )

    assert len(records) == 4
    assert sorted((r["id"], r["n"]) for r in records) == [
        ("a", 1),
        ("a", 2),
        ("b", 1),
        ("b", 2),
    ]
