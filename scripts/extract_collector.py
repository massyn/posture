"""Manual smoke test for a single collector: walk every resource in its
manifest, capped at 20 raw records each, with debug logging on.

    python scripts/extract_collector.py crowdstrike_cspm
    python scripts/extract_collector.py wiz
"""

import argparse
import json
import logging
from datetime import date, datetime
from pathlib import Path

from posture import CCM
from posture.exceptions import PostureError

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

_RECORD_LIMIT = 20

_args = argparse.ArgumentParser(description=__doc__)
_args.add_argument("source", help="collector name, e.g. crowdstrike_cspm")
source = _args.parse_args().source


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

ccm = CCM(source, record_limit=_RECORD_LIMIT)

for resource in ccm.tables():
    try:
        df = ccm.collect(resource)
    except PostureError as exc:
        print(f"{source}.{resource}: FAILED — {exc}")
        continue

    output_path = output_dir / f"{source}_{resource}.json"
    write_records_json(df, output_path)
    print(f"Wrote {len(df)} {source}.{resource} to {output_path}")
    print(ccm.report(resource))
