"""Manual smoke test for a single collector: walk every resource in its
manifest, capped at 20 raw records each, with debug logging on.

Uses collect_page() rather than collect() — each page is written to its own
uuid'ed file inside a per-resource folder as it arrives, so nothing here
accumulates a whole resource in memory.

    python scripts/extract_collector.py crowdstrike_cspm
    python scripts/extract_collector.py wiz
    python scripts/extract_collector.py crowdstrike_cspm.vulnerabilities
"""

import argparse
import json
import logging
import uuid
from datetime import date, datetime
from pathlib import Path

from dotenv import load_dotenv

from posture import CCM
from posture.exceptions import PostureError

load_dotenv()

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

_args = argparse.ArgumentParser(description=__doc__)
_args.add_argument(
    "source", help="collector name, e.g. crowdstrike_cspm, or collector.table"
)
_source_arg = _args.parse_args().source
source, _, _table_filter = _source_arg.partition(".")


def _json_default(value: object) -> str:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return str(value)


def write_records_json(df, path: Path) -> None:
    with path.open("w", encoding="utf-8") as fp:
        fp.write("[")
        for i, record in enumerate(df.to_dict(orient="records")):
            if i:
                fp.write(",")
            fp.write("\n  ")
            json.dump(record, fp, default=_json_default)
        fp.write("\n]")


output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

ccm = CCM(source)

resources = [_table_filter] if _table_filter else ccm.tables()

for resource in resources:
    resource_dir = output_dir / f"{source}_{resource}"
    resource_dir.mkdir(exist_ok=True)

    page_count = 0
    record_count = 0
    try:
        for df in ccm.collect_page(resource):
            page_path = resource_dir / f"{uuid.uuid4().hex}.json"
            write_records_json(df, page_path)
            page_count += 1
            record_count += len(df)
    except PostureError as exc:
        print(f"{source}.{resource}: FAILED — {exc}")
        continue

    print(
        f"Wrote {record_count} {source}.{resource} records across "
        f"{page_count} pages to {resource_dir}"
    )
    print(ccm.report(resource))
