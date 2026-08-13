"""Disk-backed spill for raw records, so a Collector never has to hold every
page of a resource in memory simultaneously during a long pagination run —
the actual memory-exhaustion pattern seen on MDE's machine_vulnerabilities
during Patch Tuesday CVE spikes (many large pages, retries prolonging the
fetch phase, all held in one growing in-memory list at once).

One SpillStore per Collector instance, backed by one unique temp directory
per instance (tempfile.mkdtemp() guarantees this — no fixed path, so a new
run can never see a previous run's, or another instance's, files). Nothing
written through it is retained longer than necessary:

- Transient reads (a resource nobody else needs) delete their file the
  moment they've been read back.
- Cached reads (a resource reused via manifest 'derived_from'/'requires')
  persist until Collector.flush_cache() deletes them, or the run ends.
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
from typing import Any

logger = logging.getLogger("posture.spill")

_DIR_PREFIX = "posture-spill-"
_ORPHAN_MAX_AGE_SECONDS = 24 * 60 * 60


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
    def read_records(path: Path) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    records.append(json.loads(line))
        return records

    @staticmethod
    def delete(path: Path) -> None:
        path.unlink(missing_ok=True)

    def close(self) -> None:
        shutil.rmtree(self._dir, ignore_errors=True)
