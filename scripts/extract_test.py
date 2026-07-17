"""Manual smoke test: extract resources from every configured source and save
them to local JSON.

Requires credentials for whichever sources you want to test, either in the
environment or a .env file in the current directory:
    CROWDSTRIKE_CLIENT_ID / CROWDSTRIKE_CLIENT_SECRET
    OKTA_DOMAIN / OKTA_TOKEN
    WORKSPACEONE_CLIENT_ID / WORKSPACEONE_CLIENT_SECRET / WORKSPACEONE_API_SERVER /
        WORKSPACEONE_TOKEN_URL
    UPGUARD_API_KEY
    JAMF_URL / JAMF_CLIENT_ID / JAMF_CLIENT_SECRET
    INTUNE_TENANT_ID / INTUNE_CLIENT_ID / INTUNE_CLIENT_SECRET
    MDE_TENANT_ID / MDE_CLIENT_ID / MDE_CLIENT_SECRET

A source with no credentials configured is skipped, not fatal.

    python scripts/extract_test.py
"""

import json
import logging
from datetime import date, datetime
from pathlib import Path

from posture import CCM
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

SOURCES_AND_RESOURCES = {
    "crowdstrike": [
        "hosts",
        "vulnerabilities",
        "vulnerability_remediations",
        "zero_trust_assessment",
        "zero_trust_assessment_os_signals",
        "zero_trust_assessment_sensor_signals",
    ],
    "okta": [
        "users",
        "devices",
        "device_users",
    ],
    "workspaceone": [
        "computers",
    ],
    "upguard": [
        "vendors",
        "domains",
        "breached_identities",
        "organisation",
        "vendor_risks",
    ],
    "jamf": [
        "computers_inventory",
        "computers_inventory_detail",
        "mobile_devices",
        "policies",
        "categories",
        "buildings",
        "departments",
    ],
    "intune": [
        "managed_devices",
        "users",
        "device_configurations",
        "managed_device_detail",
        "device_configuration_detail",
        "device_compliance_policies",
        "attack_simulations",
        "attack_simulation_users",
    ],
    "mde": [
        "machines",
        "vulnerabilities",
        "device_av_info",
        "machine_vulnerabilities",
    ],
}

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for source, resources in SOURCES_AND_RESOURCES.items():
    try:
        ccm = CCM(source)
    except ValueError as exc:
        print(f"{source}: SKIPPED — {exc}")
        continue

    for resource in resources:
        try:
            df = ccm.collect(resource)
        except PostureError as exc:
            print(f"{source}.{resource}: FAILED — {exc}")
            continue

        output_path = output_dir / f"{source}_{resource}.json"
        write_records_json(df, output_path)
        print(f"Wrote {len(df)} {source}.{resource} to {output_path}")
        print(ccm.report(resource))
