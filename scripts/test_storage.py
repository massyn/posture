"""Manual smoke test for every storage backend, driven off a real Cloudflare
collection.

Collects every resource Cloudflare exposes, then writes each one through
every backend/mode combination:

    csv/json/parquet, truncate (overwrite in place)
    csv/json/parquet, append   (dated history folder)
    sqlite,           truncate ("once" — table recreated)
    sqlite,           append   (rows added to the existing table)
    duckdb,           truncate ("once" — table recreated)
    duckdb,           append   (rows added to the existing table)
    postgres,         truncate (skipped if POSTURE_POSTGRES_DSN isn't set)
    postgres,         append   (skipped if POSTURE_POSTGRES_DSN isn't set)

Not a pytest test (deliberately outside tests/, and not named so pytest
would collect it) — it makes real network calls against Cloudflare and a
real Postgres database, so it's a script to run by hand, not part of CI.

Requires CLOUDFLARE_API_TOKEN (and CLOUDFLARE_ACCOUNT_ID, if the tenant
needs it) in the environment/.env. POSTURE_POSTGRES_DSN is optional — the
postgres backend is skipped entirely when it isn't set.

    python scripts/test_storage.py
"""

import os
from pathlib import Path

from posture import CCM, write_storage

_OUTPUT_DIR = Path("output") / "cloudflare"
# Separate db files per mode — writing truncate then append against the same
# file would recreate the table and then immediately double its rows via the
# append that follows. One file per mode keeps each mode's effect visible.
_SQLITE_TRUNCATE_PATH = _OUTPUT_DIR / "data.db"
_SQLITE_APPEND_PATH = _OUTPUT_DIR / "append.db"
_DUCKDB_TRUNCATE_PATH = _OUTPUT_DIR / "data.duckdb"
_DUCKDB_APPEND_PATH = _OUTPUT_DIR / "append.duckdb"


def main() -> None:
    ccm = CCM("cloudflare")

    backends = [
        ("csv", {"path": str(_OUTPUT_DIR)}),
        ("json", {"path": str(_OUTPUT_DIR)}),
        ("parquet", {"path": str(_OUTPUT_DIR)}),
    ]
    sqlite_config = {
        "truncate": {"path": str(_SQLITE_TRUNCATE_PATH)},
        "append": {"path": str(_SQLITE_APPEND_PATH)},
    }
    duckdb_config = {
        "truncate": {"path": str(_DUCKDB_TRUNCATE_PATH)},
        "append": {"path": str(_DUCKDB_APPEND_PATH)},
    }
    if os.environ.get("POSTURE_POSTGRES_DSN"):
        backends.append(("postgres", None))  # dsn comes from POSTURE_POSTGRES_DSN
    else:
        print("POSTURE_POSTGRES_DSN not set — skipping postgres backend")

    for resource in ccm.tables():
        print(f"collecting '{resource}'...")
        df = ccm.collect(resource)
        print(f"  {len(df)} records")

        for storage, config in backends:
            for mode in ("truncate", "append"):
                print(f"  writing {storage} ({mode})...")
                write_storage(df, storage, resource, config=config, mode=mode)

        for mode, config in sqlite_config.items():
            print(f"  writing sqlite ({mode})...")
            write_storage(df, "sqlite", resource, config=config, mode=mode)

        for mode, config in duckdb_config.items():
            print(f"  writing duckdb ({mode})...")
            write_storage(df, "duckdb", resource, config=config, mode=mode)

    ccm.flush_cache()
    print(
        f"done — see {_OUTPUT_DIR}/, {_SQLITE_TRUNCATE_PATH}, {_SQLITE_APPEND_PATH}, "
        f"{_DUCKDB_TRUNCATE_PATH}, {_DUCKDB_APPEND_PATH}"
    )


if __name__ == "__main__":
    main()
