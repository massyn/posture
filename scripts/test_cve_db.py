"""Live smoke test for the cve_db collector (public, unauthenticated).

Pages through each resource with ``collect_page()``, printing every page's
size, then a summary: total rows, unique CVE ids, and (for ``cve_summary``)
the most recently published CVE.

    python scripts/test_cve_db.py
    python scripts/test_cve_db.py --page-size 10000
    python scripts/test_cve_db.py --resource cve_summary
"""

from __future__ import annotations

import argparse
import time

from dotenv import load_dotenv

from posture import CCM

load_dotenv()

_RESOURCES = ("cve_summary", "cve_cpe")


def run(resource: str, page_size: int | None) -> None:
    config = {"page_size": page_size} if page_size else None
    ccm = CCM("cve_db", config)
    started = time.monotonic()

    cve_ids: set[str] = set()
    total_rows = 0
    latest: tuple[object, str] | None = None

    print(f"\n=== {resource} (page_size={ccm._page_size:,}) ===")
    for number, page in enumerate(ccm.collect_page(resource), start=1):
        total_rows += len(page)
        cve_ids.update(page["cve_id"].dropna())
        if "published" in page.columns and page["published"].notna().any():
            row = page.loc[page["published"].idxmax()]
            if latest is None or row["published"] > latest[0]:
                latest = (row["published"], row["cve_id"])
        print(
            f"page {number:>4}: {len(page):>7,} rows "
            f"(running total {total_rows:,}, {time.monotonic() - started:.0f}s)"
        )

    print(f"total rows:      {total_rows:,}")
    print(f"unique CVE ids:  {len(cve_ids):,}")
    if latest is not None:
        print(f"latest CVE:      {latest[1]} (published {latest[0]})")
    print(f"elapsed:         {time.monotonic() - started:.0f}s")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--resource", choices=_RESOURCES, help="default: both")
    parser.add_argument("--page-size", type=int, help="rows per page (default 25,000)")
    args = parser.parse_args()

    for resource in [args.resource] if args.resource else _RESOURCES:
        run(resource, args.page_size)


if __name__ == "__main__":
    main()
