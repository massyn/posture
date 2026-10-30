"""Qualys VMDR tables, read through the ``/fo/`` XML API (see ``fo_api.py``).

- ``vm_hosts``: the host list (``/api/5.0/fo/asset/host/``).
- ``vm_knowledgebase``: the QID catalogue (severity, CVSS, CVE), one row per
  QID, not a per-host finding (``/api/4.0/fo/knowledge_base/vuln/``).
- ``vm_detections``: one row per (host, QID), derived from the per-host
  detection list (``/api/4.0/fo/asset/host/vm/detection/``), fetched
  internally as ``host_detections``.

The ``/api/2.0`` paths of all three are Qualys End-of-Service (EOS warning
observed on responses) in favour of the versions above, with the same request
params and XML response shape.

kwargs are passed through as Qualys query parameters and win over the
built-in defaults for the same name.
"""

from __future__ import annotations

from typing import Any

from posture.collectors.qualys.fo_api import FoApi

_HOST_LIST_PATH = "/api/5.0/fo/asset/host/"
_KB_PATH = "/api/4.0/fo/knowledge_base/vuln/"
_HOST_DETECTION_PATH = "/api/4.0/fo/asset/host/vm/detection/"

MANIFEST: dict[str, dict[str, Any]] = {
    "vm_hosts": {
        "columns": {
            "host_id": ("ID", "str"),
            "ip": ("IP", "str"),
            "ipv6": ("IPV6", "str"),
            "tracking_method": ("TRACKING_METHOD", "str"),
            "dns_name": ("DNS", "str"),
            "netbios_name": ("NETBIOS", "str"),
            "os": ("OS", "str"),
            "qg_host_id": ("QG_HOSTID", "str"),
            "cloud_provider": ("CLOUD_PROVIDER", "str"),
            "cloud_service": ("CLOUD_SERVICE", "str"),
            "cloud_resource_id": ("CLOUD_RESOURCE_ID", "str"),
            "last_boot": ("LAST_BOOT", "datetime"),
            "last_vuln_scan": ("LAST_VULN_SCAN_DATETIME", "datetime"),
            "last_vm_scan": ("LAST_VM_SCANNED_DATE", "datetime"),
            "last_pc_scan": ("LAST_PC_SCANNED_DATE", "datetime"),
            "agent_version": ("AGENT_INFO.AGENT_VERSION", "str"),
            "agent_status": ("AGENT_INFO.AGENT_STATUS", "str"),
            "agent_last_checked_in": ("AGENT_INFO.LAST_CHECKED_IN_DATE", "datetime"),
            "tags": ("TAGS.TAG", "json"),
        },
    },
    "vm_knowledgebase": {
        "columns": {
            "qid": ("QID", "str"),
            "vuln_type": ("VULN_TYPE", "str"),
            "severity": ("SEVERITY_LEVEL", "int"),
            "title": ("TITLE", "str"),
            "category": ("CATEGORY", "str"),
            "patchable": ("PATCHABLE", "bool"),
            "pci_flag": ("PCI_FLAG", "bool"),
            "published": ("PUBLISHED_DATETIME", "datetime"),
            "last_modified": ("LAST_SERVICE_MODIFICATION_DATETIME", "datetime"),
            "cvss_base": ("CVSS.BASE", "float"),
            "cvss3_base": ("CVSS_V3.BASE", "float"),
            "cve_list": ("CVE_LIST.CVE", "json"),
        },
    },
    "vm_detections": {
        "derived_from": "host_detections",
        "record_path": "DETECTION_LIST.DETECTION",
        "columns": {
            "host_id": ("$parent.ID", "str"),
            "host_ip": ("$parent.IP", "str"),
            "host_dns_name": ("$parent.DNS", "str"),
            "host_os": ("$parent.OS", "str"),
            "qid": ("QID", "str"),
            "detection_type": ("TYPE", "str"),
            "severity": ("SEVERITY", "int"),
            "port": ("PORT", "int"),
            "protocol": ("PROTOCOL", "str"),
            "results": ("RESULTS", "str"),
            "status": ("STATUS", "str"),
            "first_found": ("FIRST_FOUND_DATETIME", "datetime"),
            "last_found": ("LAST_FOUND_DATETIME", "datetime"),
            "last_tested": ("LAST_TEST_DATETIME", "datetime"),
            "last_updated": ("LAST_UPDATE_DATETIME", "datetime"),
            "is_ignored": ("IS_IGNORED", "bool"),
            "is_disabled": ("IS_DISABLED", "bool"),
        },
    },
}


class VmApi:
    resources = ("vm_hosts", "vm_knowledgebase", "host_detections")

    def __init__(self, fo: FoApi) -> None:
        self._fo = fo

    def fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "vm_hosts":
            return self._fo.fetch_list_page(
                cursor,
                path=_HOST_LIST_PATH,
                params={
                    "action": "list",
                    "details": "All/AGs",
                    "show_tags": 1,
                    "host_metadata": "all",
                    **kwargs,
                },
                list_path=("RESPONSE", "HOST_LIST", "HOST"),
            )
        if resource == "vm_knowledgebase":
            return self._fo.fetch_list_page(
                cursor,
                path=_KB_PATH,
                params={"action": "list", "details": "All", **kwargs},
                list_path=("RESPONSE", "VULN_LIST", "VULN"),
                # KnowledgeBase rejects `truncation_limit` outright (400):
                # unlike the asset/host/* endpoints, it isn't a paginated
                # list API and doesn't accept the param at all.
                paginated=False,
            )
        return self._fo.fetch_list_page(
            cursor,
            path=_HOST_DETECTION_PATH,
            params={"action": "list", **kwargs},
            list_path=("RESPONSE", "HOST_LIST", "HOST"),
        )
