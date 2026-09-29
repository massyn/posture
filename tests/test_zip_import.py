"""posture must work when imported from a zip archive, not just a directory.

Snowflake stored procedures (and zipapps generally) import packages straight
out of a zip, where ``Path(__file__).parent / "x.json"`` does not exist on
disk. Collectors that ship a bundled schema file must read it through
``importlib.resources`` instead. This test runs the import in a subprocess so
the zipped copy of posture is guaranteed to shadow the one under test.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import posture

_SRC_ROOT = Path(posture.__file__).parent.parent

_PROBE = """
import json, posture
catalog = posture.catalog()
print(json.dumps({
    "file": posture.__file__,
    "resources": {
        name: sorted(catalog[name]["resources"])
        for name in ("jira", "salesforce", "servicenow")
    },
}))
"""


def _zip_package(dest: Path) -> Path:
    archive = dest / "posture.zip"
    package_dir = _SRC_ROOT / "posture"
    with zipfile.ZipFile(archive, "w") as zf:
        for path in package_dir.rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts:
                zf.write(path, path.relative_to(_SRC_ROOT).as_posix())
    return archive


def test_catalog_loads_bundled_schemas_from_zip(tmp_path: Path) -> None:
    archive = _zip_package(tmp_path)
    env = {
        **os.environ,
        "PYTHONPATH": str(archive),
        "POSTURE_VERSION_CHECK": "0",
    }

    result = subprocess.run(
        [sys.executable, "-c", _PROBE],
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp_path,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    probe = json.loads(result.stdout.strip().splitlines()[-1])
    assert Path(probe["file"]).is_relative_to(archive)
    expected = {
        name: sorted(posture.catalog()[name]["resources"])
        for name in ("jira", "salesforce", "servicenow")
    }
    assert probe["resources"] == expected
    assert all(probe["resources"].values())
