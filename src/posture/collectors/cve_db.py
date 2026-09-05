"""cve-db collector.

Raw ``requests`` against `cve-db <https://cve-db.pages.dev>`_, a free,
unauthenticated static export of NVD CVE data — no vendor SDK, and (like
``endoflife.py``) no credential to gate this collector: ``config_keys`` has
no required keys.

``base_url`` (config key / ``CVE_DB_BASE_URL``, default
``https://cve-db.pages.dev``) is optional, same normalised-host shape as
Healthchecks' ``api_url``/DNSimple's ``endpoint``, for anyone mirroring the
static export elsewhere.

**Manifest-driven, not hardcoded.** ``GET {base_url}/manifest.json`` is the
one thing this collector never assumes — it declares the resources on offer
(``_meta.tables``) and, per resource, the list of per-year Parquet file URLs
to pull (``<resource>.files.parquet``). Fetched once per instance (cached on
``self._file_manifest``, populated lazily on first ``collect()`` — no
network call at construction) and used as the page list for both resources:
one page per file, cursor = index into that list, same bounded-per-item
pagination shape as ``endoflife.py``'s one-page-per-product loop. A failure
partway through still yields ``IncompleteCollection``, not a partial
snapshot silently treated as complete.

Two resources, matching ``manifest.json``'s two tables one-for-one:

- ``cve_summary`` — one row per CVE: NVD status, CVSS/CWE/EPSS/KEV summary
  fields.
- ``cve_cpe`` — one row per CPE match entry for a CVE (``cve_id`` joins back
  to ``cve_summary.cve_id``), sourced from its own file set rather than
  nested under ``cve_summary`` — not declared ``derived_from`` since it is
  fetched independently, not exploded out of a parent record.

**Schema note — allowlist, not normalisation.** Column types here are taken
directly off ``manifest.json``'s own declared ``type`` per field
(``string``/``integer``/``float``/``timestamp`` -> ``str``/``int``/
``float``/``datetime``) — including fields that read like booleans
(``is_app``, ``is_kev``, ...) but which the source itself types ``integer``
(0/1), so they stay ``int`` rather than being reinterpreted as ``bool``.

**Null sentinels.** cve-db's Parquet export uses the literal string ``"N/A"``
as its null marker across both tables (`epss`, `epss_percentile`,
`kev_date_added` when a CVE has no EPSS/KEV data, but also scattered through
otherwise-string columns like `cwe`/`cvss_version`/`base_score` for very old
or unscored CVEs). A second, narrower sentinel shows up only on the CVSS
sub-metric flags (`is_remote`/`is_adjacent`/`is_local`/`is_physical`/
`requires_auth`/`requires_user_interaction`): pre-CVSS CVEs from the late
1990s (verified against the real `cve_summary_1999` file, 39 rows) carry an
**empty string**, not `"N/A"`, on exactly those columns — the same "no CVSS
vector to derive this from" case, just a different literal. Both sentinels
normalise to ``None`` in ``_fetch_parquet`` before records ever reach
``parse()``, the same as any other collector's source-specific null
convention (e.g. MDE's tri-state bool strings), so a missing EPSS score or a
pre-CVSS-era CVE doesn't spam an "unparseable float"/"unparseable int"
warning per row.
"""

from __future__ import annotations

import logging
from io import BytesIO
from typing import Any, ClassVar

import pandas as pd

from posture.base import Collector, RateLimitedSignal

logger = logging.getLogger("posture.collectors.cve_db")

_DEFAULT_BASE_URL = "https://cve-db.pages.dev"

MANIFEST: dict[str, dict[str, Any]] = {
    "cve_summary": {
        "columns": {
            "cve_id": ("cve_id", "str"),
            "published": ("published", "datetime"),
            "last_modified": ("last_modified", "datetime"),
            "vuln_status": ("vuln_status", "str"),
            "is_app": ("is_app", "int"),
            "is_os": ("is_os", "int"),
            "is_hardware": ("is_hardware", "int"),
            "product": ("product", "str"),
            "cwe": ("cwe", "str"),
            "cvss_version": ("cvss_version", "str"),
            "base_score": ("base_score", "float"),
            "base_severity": ("base_severity", "str"),
            "is_remote": ("is_remote", "int"),
            "is_adjacent": ("is_adjacent", "int"),
            "is_local": ("is_local", "int"),
            "is_physical": ("is_physical", "int"),
            "requires_auth": ("requires_auth", "int"),
            "requires_user_interaction": ("requires_user_interaction", "int"),
            "ssvc_exploitation": ("ssvc_exploitation", "str"),
            "ssvc_automatable": ("ssvc_automatable", "str"),
            "has_patch_reference": ("has_patch_reference", "int"),
            "cvss_vector": ("cvss_vector", "str"),
            "epss": ("epss", "float"),
            "epss_percentile": ("epss_percentile", "float"),
            "is_kev": ("is_kev", "int"),
            "kev_date_added": ("kev_date_added", "datetime"),
        }
    },
    "cve_cpe": {
        "columns": {
            "cve_id": ("cve_id", "str"),
            "criteria": ("criteria", "str"),
            "vendor": ("vendor", "str"),
            "product": ("product", "str"),
            "version": ("version", "str"),
            "version_start_including": ("version_start_including", "str"),
            "version_start_excluding": ("version_start_excluding", "str"),
            "version_end_including": ("version_end_including", "str"),
            "version_end_excluding": ("version_end_excluding", "str"),
            "vulnerable": ("vulnerable", "int"),
        }
    },
}


class CveDbCollector(Collector):
    env_prefix = "CVE_DB"
    display_name = "cve-db"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {"base_url": False}
    url_config_keys = ("base_url",)

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        self._base_url = self._config.get("base_url", _DEFAULT_BASE_URL)
        # Resource -> list of Parquet file URLs, read off manifest.json.
        # None until the first _fetch_page call — no network call at
        # construction, per the locked config-resolution rule.
        self._file_manifest: dict[str, list[str]] | None = None

    def _authenticate(self) -> None:
        # Public data, nothing to authenticate — session needs no headers.
        pass

    def _ensure_file_manifest(self) -> dict[str, list[str]]:
        if self._file_manifest is None:
            response = self._session.get(f"{self._base_url}/manifest.json", timeout=30)
            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                raise RateLimitedSignal(
                    retry_after=float(retry_after) if retry_after else None
                )
            response.raise_for_status()
            data = response.json()
            self._file_manifest = {
                name: info["files"]["parquet"]
                for name, info in data.items()
                if name != "_meta"
            }
        return self._file_manifest

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource not in MANIFEST:
            raise ValueError(f"Unknown resource '{resource}'")

        files = self._ensure_file_manifest().get(resource, [])
        if not files:
            return [], None

        index = cursor or 0
        records = self._fetch_parquet(files[index])
        next_cursor = index + 1 if index + 1 < len(files) else None
        return records, next_cursor

    def _fetch_parquet(self, url: str) -> list[dict[str, Any]]:
        response = self._session.get(url, timeout=60)
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitedSignal(
                retry_after=float(retry_after) if retry_after else None
            )
        response.raise_for_status()

        df = pd.read_parquet(BytesIO(response.content)).astype(object)
        df = df.replace({"N/A": None, "": None})
        df = df.where(df.notna(), None)
        return df.to_dict("records")
