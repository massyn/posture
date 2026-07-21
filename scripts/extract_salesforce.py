"""Minimal single-source extract: Salesforce only.

Unlike extract_test.py (which walks every registered source off catalog()),
this is the pattern to copy when you only care about one source: construct
the CCM, loop the resources you actually want, handle IncompleteCollection
per-resource, and read the report.

Credentials come from .env / environment — SALESFORCE_USERNAME,
SALESFORCE_PASSWORD, SALESFORCE_TOKEN (and SALESFORCE_DOMAIN if using a
sandbox).

    python scripts/extract_salesforce.py
"""

import logging
from pathlib import Path

from posture import CCM
from posture.exceptions import PostureError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

RESOURCES = [
    "fixed_asset__c",
    "krow__location__c",
    "krow__project_resources__c",
    "domain__c",
    "krow__team__c",
]

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

ccm = CCM("salesforce")

for resource in RESOURCES:
    try:
        df = ccm.collect(resource)
    except PostureError as exc:
        print(f"{resource}: FAILED — {exc}")
        continue

    if df.empty:
        print(f"{resource}: 0 rows — skipping CSV write")
        print(ccm.report(resource))
        continue

    output_path = output_dir / f"salesforce_{resource}.csv"
    df.to_csv(output_path, index=False)
    print(f"Wrote {len(df)} rows to {output_path}")
    print(ccm.report(resource))