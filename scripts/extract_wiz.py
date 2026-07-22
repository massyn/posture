import logging

from posture import CCM
from posture.exceptions import PostureError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

ccm = CCM("wiz")

for resource in ccm.tables():
    try:
        df = ccm.collect(resource)
    except PostureError as exc:
        print(f"{resource}: FAILED — {exc}")
        continue

    if df.empty:
        print(f"{resource}: 0 rows — skipping CSV write")
        print(ccm.report(resource))
        continue

    df.to_csv(f"output/wiz_{resource}.csv", index=False)
    print(f"Wrote {len(df)} rows to wiz_{resource}.csv")
    print(ccm.report(resource))