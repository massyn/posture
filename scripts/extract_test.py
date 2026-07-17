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

from pathlib import Path

from posture import CCM
from posture.exceptions import PostureError

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
        output_path.write_text(
            df.to_json(orient="records", date_format="iso", indent=2)
        )
        print(f"Wrote {len(df)} {source}.{resource} to {output_path}")
        print(ccm.report(resource))
