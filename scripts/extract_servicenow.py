"""Minimal single-source extract: ServiceNow only.

Same pattern as extract_salesforce.py: construct the CCM, loop the
resources you actually want, handle IncompleteCollection per-resource, and
read the report. Unlike extract_salesforce.py, the resource list isn't
hardcoded here — it's read straight off servicenow.json (the same schema
file the collector itself loads its manifest from), so adding a table to
that file picks it up here for free.

Credentials come from .env / environment. Default auth mode is OAuth2
(SERVICENOW_CLIENT_ID/CLIENT_SECRET/USERNAME/PASSWORD, plus
SERVICENOW_INSTANCE) — see the "switch to basic auth" block below for how
to flick to basic instead.

    python scripts/extract_servicenow.py
"""

import json
import logging
from pathlib import Path

from posture import CCM
from posture.exceptions import PostureError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

SCHEMA_PATH = Path("src/posture/collectors/servicenow.json")
RESOURCES = list(json.loads(SCHEMA_PATH.read_text()))

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

# Default: OAuth2 (resource-owner password grant). Needs SERVICENOW_INSTANCE,
# SERVICENOW_CLIENT_ID, SERVICENOW_CLIENT_SECRET, SERVICENOW_USERNAME,
# SERVICENOW_PASSWORD in the environment/.env — auth_type defaults to
# "oauth2" so it doesn't need to be passed explicitly.
ccm = CCM("servicenow")

# --- To switch to basic auth instead, comment out the line above and use:
#
# ccm = CCM("servicenow", {"auth_type": "basic"})
#
# This only needs SERVICENOW_INSTANCE, SERVICENOW_USERNAME, and
# SERVICENOW_PASSWORD — no client_id/client_secret. auth_type can also be
# set via the SERVICENOW_AUTH_TYPE env var instead of passing it here:
#
# os.environ["SERVICENOW_AUTH_TYPE"] = "basic"
# ccm = CCM("servicenow")

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

    output_path = output_dir / f"servicenow_{resource}.csv"
    df.to_csv(output_path, index=False)
    print(f"Wrote {len(df)} rows to {output_path}")
    print(ccm.report(resource))
