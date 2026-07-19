"""Manual smoke test: walk posture's own catalog(), extract every resource of
every registered source, and save the results to local JSON.

Sources and resources are not hardcoded here — they're read straight off
``posture.catalog()``, so this script never drifts out of sync with what the
library actually offers. Set credentials for whichever sources you want to
test, either in the environment or a .env file in the current directory; see
``catalog()["<source>"]["required_config"]`` (or the README) for the env var
names. A source with no credentials configured is skipped, not fatal.

    python scripts/extract_test.py
"""

import json
import logging
import os
import time
from datetime import date, datetime
from pathlib import Path

from posture import CCM, catalog
from posture.exceptions import PostureError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)


def _json_default(value: object) -> str:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return str(value)


def write_records_json(df, path: Path) -> None:
    """Stream records to disk as JSON, one at a time.

    pandas' df.to_json() builds the entire output as a single in-memory
    buffer via its ujson encoder, which can overflow on large DataFrames
    (observed on Windows: "OverflowError: Could not reserve memory block").
    Writing incrementally with the stdlib json module avoids ever holding
    the full serialised document in memory.
    """
    with path.open("w", encoding="utf-8") as fp:
        fp.write("[")
        for i, record in enumerate(df.to_dict(orient="records")):
            if i:
                fp.write(",")
            fp.write("\n  ")
            json.dump(record, fp, default=_json_default)
        fp.write("\n]")


def print_summary_table(rows: list[dict]) -> None:
    headers = ["source", "status", "records", "duration_seconds"]
    widths = [
        (
            max(len(headers[i]), *(len(str(row[headers[i]])) for row in rows))
            if rows
            else len(headers[i])
        )
        for i in range(len(headers))
    ]

    def _format_row(values: list[str]) -> str:
        return "  ".join(value.ljust(widths[i]) for i, value in enumerate(values))

    print()
    print(_format_row(headers))
    print(_format_row(["-" * w for w in widths]))
    for row in rows:
        print(_format_row([str(row[h]) for h in headers]))


output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

summary: list[dict] = []

for source, info in catalog().items():
    missing_env = [
        env_var
        for env_var in info["required_config"].values()
        if env_var not in os.environ
    ]
    if missing_env:
        print(f"{source}: SKIPPED — missing env var(s): {', '.join(missing_env)}")
        summary.append(
            {
                "source": source,
                "status": "skipped",
                "records": 0,
                "duration_seconds": 0.0,
            }
        )
        continue

    try:
        ccm = CCM(source)
    except ValueError as exc:
        print(f"{source}: SKIPPED — {exc}")
        summary.append(
            {
                "source": source,
                "status": "skipped",
                "records": 0,
                "duration_seconds": 0.0,
            }
        )
        continue

    started = time.perf_counter()
    records = 0
    status = "ok"

    for resource in info["resources"]:
        try:
            df = ccm.collect(resource)
        except PostureError as exc:
            print(f"{source}.{resource}: FAILED — {exc}")
            status = "partial"
            continue

        output_path = output_dir / f"{source}_{resource}.json"
        write_records_json(df, output_path)
        records += len(df)
        print(f"Wrote {len(df)} {source}.{resource} to {output_path}")
        print(ccm.report(resource))

    summary.append(
        {
            "source": source,
            "status": status,
            "records": records,
            "duration_seconds": round(time.perf_counter() - started, 2),
        }
    )

print_summary_table(summary)
