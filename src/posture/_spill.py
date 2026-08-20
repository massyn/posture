"""Disk-backed spill for raw records reused across resources, so a Collector
never has to hold a whole resource in memory just because a second resource
(via manifest 'derived_from'/'requires') needs its raw records again later.

Plain, non-reused resources no longer spill to disk at all: Collector.
collect_page() streams each fetched page straight through parse() and
discards it, so peak memory is one page, not one resource. Disk spill now
exists only for the reuse case — the fetch phase of that reused resource
still writes each page to disk as it goes, and its records are replayed back
in bounded batches (read_pages), never as a single in-memory list.

One SpillStore per Collector instance, backed by one unique temp directory
per instance (tempfile.mkdtemp() guarantees this — no fixed path, so a new
run can never see a previous run's, or another instance's, files). Nothing
written through it is retained longer than necessary:

- Cached resources (reused via manifest 'derived_from'/'requires') persist
  until Collector.flush_cache() deletes them, or the run ends.
- The whole directory is removed at process exit (atexit) as a backstop,
  and a sweep on the next Collector's construction removes any directory
  left behind by a run that never reached its own cleanup (e.g. killed by
  the OS on OOM, where atexit doesn't run) — matched only by posture's own
  prefix and an age cutoff, so it never touches unrelated temp files or the
  current run's own (too young) directory.
"""

from __future__ import annotations

import atexit
import json
import logging
import shutil
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Iterator

logger = logging.getLogger("posture.spill")

_DIR_PREFIX = "posture-spill-"
_ORPHAN_MAX_AGE_SECONDS = 24 * 60 * 60

# Batch size for replaying a cached resource's records back off disk. Bounds
# memory the same way collect_page() bounds it for a fresh fetch — a cached
# derived_from/requires parent is replayed in chunks of this size rather than
# as one list, regardless of how many original API pages it was written in.
_REPLAY_BATCH_SIZE = 10_000


def _sweep_orphans() -> None:
    base = Path(tempfile.gettempdir())
    try:
        candidates = list(base.glob(f"{_DIR_PREFIX}*"))
    except OSError:
        return
    now = time.time()
    for path in candidates:
        try:
            if now - path.stat().st_mtime < _ORPHAN_MAX_AGE_SECONDS:
                continue
            shutil.rmtree(path, ignore_errors=True)
        except OSError:
            continue


class SpillStore:
    def __init__(self) -> None:
        _sweep_orphans()
        self._dir = Path(tempfile.mkdtemp(prefix=_DIR_PREFIX))
        atexit.register(self.close)

    def new_path(self, key: str) -> Path:
        return self._dir / f"{uuid.uuid4().hex}-{key}.jsonl"

    @staticmethod
    def read_pages(path: Path) -> Iterator[list[dict[str, Any]]]:
        """Replay a spilled resource back in bounded batches, never as one list."""
        batch: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                batch.append(json.loads(line))
                if len(batch) >= _REPLAY_BATCH_SIZE:
                    yield batch
                    batch = []
        if batch:
            yield batch

    @staticmethod
    def delete(path: Path) -> None:
        path.unlink(missing_ok=True)

    def close(self) -> None:
        shutil.rmtree(self._dir, ignore_errors=True)
