"""One-off debug helper — not part of the library. Delete once resolved.

Pulls one managed device's list-endpoint record and its beta detail-endpoint
record, side by side, so we can see which of the "null" fields
(os_build_number, is_encrypted, compliance_state, device_guard_vbs_state,
device_guard_credential_guard_state, ...) are actually absent/null in the raw
Graph response versus something the collector's column mapping is losing.
"""

import json

from posture import CCM

ccm = CCM("intune")
ccm._ensure_authenticated()  # noqa: SLF001 - debug script, not library usage

_BASE = "https://graph.microsoft.com"

list_resp = ccm._session.get(  # noqa: SLF001
    f"{_BASE}/v1.0/deviceManagement/managedDevices",
    params={"$top": 1},
    timeout=30,
)
list_resp.raise_for_status()
devices = list_resp.json().get("value", [])
if not devices:
    raise SystemExit("no managed devices returned")

device_id = devices[0]["id"]
print(f"=== v1.0 managed_devices record (id={device_id}) ===")
print(json.dumps(devices[0], indent=2))

detail_resp = ccm._session.get(  # noqa: SLF001
    f"{_BASE}/beta/deviceManagement/managedDevices/{device_id}",
    timeout=30,
)
detail_resp.raise_for_status()
detail = detail_resp.json()
print(f"\n=== beta managed_device detail record (id={device_id}) ===")
print(json.dumps(detail, indent=2))

print("\n=== fields of interest ===")
for field in (
    "osBuildNumber",
    "isEncrypted",
    "complianceState",
    "deviceGuardVirtualizationBasedSecurityState",
    "deviceGuardLocalSystemAuthorityCredentialGuardState",
    "windowsActiveMalwareCount",
    "lastSyncDateTime",
    "userPrincipalName",
):
    present = field in detail
    print(f"{field}: present={present} value={detail.get(field)!r}")
