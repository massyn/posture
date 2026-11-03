"""Qualys Container Security tables.

Raw ``requests`` against the Container Security API (``/csapi/v1.3/...``) on
the subscription's gateway host, JWT auth shared with CSAM (see
``gateway.py``). No vendor SDK.

- ``container_images`` and ``containers``: the bulk list endpoints
  (``/csapi/v1.3/images/list``, ``/csapi/v1.3/containers/list``), not the
  paged ``/images`` and ``/containers``, whose ``pageNumber`` x ``pageSize``
  window stops at 10,000 records. The bulk endpoints take a ``limit`` and
  return the next page's URL in a ``Link: <...>; rel=next`` header, which
  becomes the cursor (the URL carries every original query parameter).
  ``container_image_repos`` is derived from each image's ``repo`` list.
- ``container_registries``: ``/csapi/v1.3/registry``, paged by
  ``pageNumber``/``pageSize`` against the response's ``count``.
- ``container_image_vulnerabilities``: one row per (image, QID), derived from
  per-image detail calls (``/csapi/v1.3/images/{sha}``, fetched internally as
  ``container_image_details``), whose ``vulnerabilities`` list carries the
  full findings; the list endpoints carry only per-severity counts. Images
  whose counts are all zero are skipped. ``container_images``' raw records
  are cached (``requires``) so the image list isn't fetched twice.

Dates come back as epoch-millisecond strings; digit-only strings in datetime
columns are converted to integers at fetch time so ``parse.py``'s epoch
handling types them.

kwargs: ``filter``, a Container Security QQL string (``"created:[now-7d ...
now]"``), passed through verbatim on ``container_images`` and ``containers``;
on ``container_image_vulnerabilities`` it narrows the images fanned out over.

Caveat: built from Qualys's public API references and Qualys-authored
scripts, not verified against a live Container Security subscription.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin

import requests

from posture.collectors.qualys.gateway import GatewayAuth

_IMAGES_LIST_PATH = "/csapi/v1.3/images/list"
_CONTAINERS_LIST_PATH = "/csapi/v1.3/containers/list"
_REGISTRY_PATH = "/csapi/v1.3/registry"
_IMAGE_DETAIL_PATH = "/csapi/v1.3/images/{sha}"

# Qualys's own bulk export script pages the list endpoints at 250.
_LIST_LIMIT = 250
_REGISTRY_PAGE_SIZE = 50
# Images fanned out per page of container_image_details.
_DETAIL_BATCH_SIZE = 100
_MAX_FANOUT_WORKERS = 5
_REQUEST_TIMEOUT_SECONDS = 180
_SEVERITY_COUNT_KEYS = tuple(f"severity{level}Count" for level in range(1, 6))

_SEVERITY_COUNT_COLUMNS: dict[str, tuple] = {
    f"severity{level}_count": (f"vulnerabilities.severity{level}Count", "int")
    for level in range(1, 6)
}

_IMAGE_PARENT_COLUMNS: dict[str, tuple] = {
    "image_sha": ("$parent.sha", "str"),
    "image_id": ("$parent.imageId", "str"),
}

MANIFEST: dict[str, dict[str, Any]] = {
    "container_images": {
        "endpoint": _IMAGES_LIST_PATH,
        "columns": {
            "image_sha": ("sha", "str"),
            "image_id": ("imageId", "str"),
            "image_uuid": ("uuid", "str"),
            "operating_system": ("operatingSystem", "str"),
            "architecture": ("architecture", "str"),
            "size": ("size", "int"),
            "repo_digests": ("repoDigests", "json"),
            "source": ("source", "json"),
            "scan_types": ("scanTypes", "json"),
            "scan_status": ("scanStatus", "str"),
            "is_docker_hub_official": ("isDockerHubOfficial", "bool"),
            "associated_containers_count": ("associatedContainersCount", "int"),
            "associated_hosts_count": ("associatedHostsCount", "int"),
            "risk_score": ("riskScore", "int"),
            "max_qds_score": ("maxQdsScore", "int"),
            "qds_severity": ("qdsSeverity", "str"),
            **_SEVERITY_COUNT_COLUMNS,
            "created": ("created", "datetime"),
            "last_updated": ("updated", "datetime"),
            "last_scanned": ("lastScanned", "datetime"),
            "last_vm_scan": ("lastVmScanDate", "datetime"),
            "last_compliance_scan": ("lastComplianceScanDate", "datetime"),
        },
    },
    "container_image_repos": {
        "derived_from": "container_images",
        "record_path": "repo",
        "columns": {
            **_IMAGE_PARENT_COLUMNS,
            "registry": ("registry", "str"),
            "repository": ("repository", "str"),
            "tag": ("tag", "str"),
        },
    },
    "container_image_vulnerabilities": {
        "derived_from": "container_image_details",
        "requires": "container_images",
        "record_path": "vulnerabilities",
        "columns": {
            **_IMAGE_PARENT_COLUMNS,
            "qid": ("qid", "str"),
            "title": ("title", "str"),
            "severity": ("severity", "int"),
            "customer_severity": ("customerSeverity", "int"),
            "qds_score": ("qdsScore", "int"),
            "risk": ("risk", "int"),
            "category": ("category", "str"),
            "type_detected": ("typeDetected", "str"),
            "result": ("result", "str"),
            "patch_available": ("patchAvailable", "bool"),
            "is_exempted": ("isExempted", "bool"),
            "cve_ids": ("cveids", "json"),
            "software": ("software", "json"),
            "first_found": ("firstFound", "datetime"),
            "last_found": ("lastFound", "datetime"),
            "published": ("published", "datetime"),
        },
    },
    "containers": {
        "endpoint": _CONTAINERS_LIST_PATH,
        "columns": {
            "container_id": ("containerId", "str"),
            "container_sha": ("sha", "str"),
            "name": ("name", "str"),
            "state": ("state", "str"),
            "image_id": ("imageId", "str"),
            "image_uuid": ("imageUuid", "str"),
            "sensor_uuid": ("sensorUuid", "str"),
            "host": ("host", "json"),
            "cluster": ("cluster", "json"),
            "is_root": ("isRoot", "bool"),
            "is_exposed_to_world": ("isExposedToWorld", "bool"),
            "risk_score": ("riskScore", "int"),
            "max_qds_score": ("maxQdsScore", "int"),
            "qds_severity": ("qdsSeverity", "str"),
            **_SEVERITY_COUNT_COLUMNS,
            "created": ("created", "datetime"),
            "last_updated": ("updated", "datetime"),
            "state_changed": ("stateChanged", "datetime"),
            "last_vm_scan": ("lastVmScanDate", "datetime"),
            "last_compliance_scan": ("lastComplianceScanned", "datetime"),
        },
    },
    "container_registries": {
        "endpoint": _REGISTRY_PATH,
        "columns": {
            "registry_uuid": ("registryUuid", "str"),
            "registry_name": ("registryName", "str"),
            "registry_uri": ("registryUri", "str"),
            "registry_type": ("registryType", "str"),
            "provider_type": ("providerType", "str"),
            "aws_account_id": ("awsAccountId", "str"),
            "aws_region": ("awsRegion", "str"),
            "docker_hub_org": ("dockerHubOrg", "str"),
            "repo_count": ("repoCount", "int"),
            "total_images": ("totalImages", "int"),
            "total_scanned_images": ("totalScannedImages", "int"),
            "total_vulnerable_images": ("totalVulnerableImages", "int"),
            "last_schedule_status": ("lastScheduleStatus", "str"),
            "created": ("created", "datetime"),
            "last_updated": ("updated", "datetime"),
            "last_scanned": ("lastScanned", "datetime"),
        },
    },
}

# Top-level raw fields holding dates, per fetched resource, so epoch strings
# can be converted before parse.py sees them.
_DATETIME_FIELDS: dict[str, frozenset[str]] = {
    resource: frozenset(
        path
        for path, kind, *_ in MANIFEST[table]["columns"].values()
        if kind == "datetime" and not path.startswith("$parent.")
    )
    for resource, table in {
        "container_images": "container_images",
        "containers": "containers",
        "container_registries": "container_registries",
        "vulnerabilities": "container_image_vulnerabilities",
    }.items()
}

_LIST_PATHS = {
    "container_images": _IMAGES_LIST_PATH,
    "containers": _CONTAINERS_LIST_PATH,
}


def _with_epoch_ints(record: dict[str, Any], fields: frozenset[str]) -> dict[str, Any]:
    return {
        key: int(value) if key in fields and str(value).isdigit() else value
        for key, value in record.items()
    }


def _has_vulnerabilities(image: dict[str, Any]) -> bool:
    """False only when the image's severity counts are all present and zero:
    a missing or unexpected summary still gets a detail call, so a change in
    the summary's shape can't silently drop findings."""
    counts = image.get("vulnerabilities")
    if not isinstance(counts, dict):
        return True
    values = [counts.get(key) for key in _SEVERITY_COUNT_KEYS]
    return any(value is None or value != 0 for value in values)


class ContainersApi:
    resources = (
        "container_images",
        "containers",
        "container_registries",
        "container_image_details",
    )

    def __init__(
        self,
        session: requests.Session,
        gateway: GatewayAuth,
        get_raw: Callable[[str, dict[str, Any]], list[dict[str, Any]]],
        fanout: Callable[..., list[dict[str, Any]]],
    ) -> None:
        self._session = session
        self._gateway = gateway
        # The collector's cached raw-records reader and resumable fan-out, so
        # image details reuse container_images' records and survive retries.
        self._get_raw = get_raw
        self._fanout = fanout

    def fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        allowed = set() if resource == "container_registries" else {"filter"}
        unknown = set(kwargs) - allowed
        if unknown:
            raise ValueError(f"Unsupported kwargs for '{resource}': {sorted(unknown)}")
        if resource == "container_registries":
            return self._fetch_registries(cursor)
        if resource == "container_image_details":
            return self._fetch_image_details(kwargs, cursor)
        return self._fetch_list(resource, kwargs, cursor)

    def _fetch_list(
        self, resource: str, kwargs: dict[str, Any], cursor: str | None
    ) -> tuple[list[dict[str, Any]], str | None]:
        if cursor is None:
            response = self._get(
                resource,
                self._gateway.url + _LIST_PATHS[resource],
                {"limit": _LIST_LIMIT, **kwargs},
            )
        else:
            response = self._get(resource, cursor, None)
        fields = _DATETIME_FIELDS[resource]
        records = [
            _with_epoch_ints(r, fields) for r in response.json().get("data") or []
        ]
        next_url = response.links.get("next", {}).get("url")
        return records, urljoin(self._gateway.url, next_url) if next_url else None

    def _fetch_registries(
        self, cursor: int | None
    ) -> tuple[list[dict[str, Any]], int | None]:
        page_number = cursor or 1
        body = self._get(
            "container_registries",
            self._gateway.url + _REGISTRY_PATH,
            {"pageNumber": page_number, "pageSize": _REGISTRY_PAGE_SIZE},
        ).json()
        data = body.get("data") or []
        fields = _DATETIME_FIELDS["container_registries"]
        records = [_with_epoch_ints(r, fields) for r in data]
        count = body.get("count")
        more = (
            page_number * _REGISTRY_PAGE_SIZE < int(count)
            if count is not None
            else len(data) == _REGISTRY_PAGE_SIZE
        )
        return records, page_number + 1 if more and data else None

    def _fetch_image_details(
        self, kwargs: dict[str, Any], cursor: tuple[tuple[str, ...], int] | None
    ) -> tuple[list[dict[str, Any]], tuple[tuple[str, ...], int] | None]:
        if cursor is None:
            shas = tuple(
                image["sha"]
                for image in self._get_raw("container_images", kwargs)
                if image.get("sha") and _has_vulnerabilities(image)
            )
            offset = 0
        else:
            shas, offset = cursor
        batch = list(shas[offset : offset + _DETAIL_BATCH_SIZE])
        records = self._fanout(
            "container_image_details", batch, self._fetch_image, _MAX_FANOUT_WORKERS
        )
        offset += _DETAIL_BATCH_SIZE
        return records, (shas, offset) if offset < len(shas) else None

    def _fetch_image(self, sha: str) -> dict[str, Any] | None:
        url = self._gateway.url + _IMAGE_DETAIL_PATH.format(sha=sha)
        response = self._get("container_image_details", url, None, missing_ok=True)
        if response is None:
            # Removed between the image list and this call.
            return None
        detail = response.json()
        fields = _DATETIME_FIELDS["vulnerabilities"]
        return {
            "sha": detail.get("sha", sha),
            "imageId": detail.get("imageId"),
            "vulnerabilities": [
                _with_epoch_ints(vuln, fields)
                for vuln in detail.get("vulnerabilities") or []
            ],
        }

    def _get(
        self,
        resource: str,
        url: str,
        params: dict[str, Any] | None,
        *,
        missing_ok: bool = False,
    ) -> requests.Response | None:
        response = self._session.get(
            url,
            params=params,
            headers=self._gateway.headers(),
            timeout=_REQUEST_TIMEOUT_SECONDS,
        )
        if missing_ok and response.status_code == 404:
            return None
        self._gateway.check(response, resource)
        return response
