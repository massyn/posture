from posture import CCM
import logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

mde = CCM("mde")
df = mde.collect("machine_vulnerabilities")
print(mde.report("machine_vulnerabilities"))