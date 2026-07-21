"""Minimal single-source extract: Qualys hosts only.

Credentials come from .env / environment — QUALYS_USERNAME, QUALYS_PASSWORD,
QUALYS_BASE_URL (the platform URL, e.g. https://qualysapi.qualys.com).

    python scripts/extract_qualys.py
"""

import logging
from pathlib import Path

from posture import CCM
from posture.exceptions import PostureError

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

ccm = CCM("qualys")

# Explicit config, instead of relying on .env / environment variables:
#
# ccm = CCM(
#     "qualys",
#     {
#         "username": os.environ["QUALYS_USERNAME"],
#         "password": os.environ["QUALYS_PASSWORD"],
#         "base_url": os.environ["QUALYS_BASE_URL"],
#     },
# )

try:
    df = ccm.collect("hosts")
except PostureError as exc:
    print(f"hosts: FAILED — {exc}")
else:
    if df.empty:
        print("hosts: 0 rows — skipping CSV write")
        print(ccm.report("hosts"))
    else:
        output_path = output_dir / "qualys_hosts.csv"
        df.to_csv(output_path, index=False)
        print(f"Wrote {len(df)} rows to {output_path}")
        print(ccm.report("hosts"))
