"""MacAdmins SOFA feed collector.

Raw ``requests`` against the MacAdmins Open and Free Software for Apple
project's SOFA feed (`https://sofafeed.macadmins.io/v1/macos_data_feed.json`)
— no vendor SDK, no auth of any kind, same "public data, unscoped" shape as
``endoflife.py``. Unlike endoflife.date, there's nothing to scope here: the
whole feed is one JSON document covering every currently-tracked macOS major
version, so a single unpaginated ``GET`` returns everything and
``config_keys`` is empty.

The feed's ``OSVersions[]`` array has one entry per major macOS version
(currently Golden Gate 27 down to Monterey 12), each with a ``Latest``
release and a ``SecurityReleases[]`` list (newest first) covering every
release of that major version. ``macos_releases`` flattens both into one row
per (major version, release) pair.

``Build`` is only present on ``OSVersions[].Latest``, not on individual
``SecurityReleases[]`` entries — it's cross-referenced onto a release's row
in ``_fetch_page`` when that release's ``ProductVersion`` matches its major
version's current ``Latest.ProductVersion``, and left null for every older
release of that major version, since the feed itself carries no build number
for those.

``exploited_cve_count`` is a straight count of ``true`` values in a
release's own ``CVEs`` dict, computed at fetch time — not an inferred or
derived business judgement, just a count over data already on the record,
the same kind of fetch-time computation as ``endoflife.py``'s
``product``/``product_label`` injection.

``macos_cves`` explodes each release's ``CVEs`` dict (``{cve_id: exploited}``)
into one row per CVE — every CVE listed against the release, not just the
exploited ones, with ``exploited`` carrying the feed's own boolean per CVE.
`record_path`'s explode machinery needs a list of dicts, not the feed's raw
dict-of-bools shape, so ``_fetch_page`` reshapes each release's ``CVEs``
dict into a ``_cves`` list of ``{"cve_id": ..., "exploited": ...}`` records
before returning it — the same "transform before parse.py ever sees it"
pattern ``qualys.py``/``cortex_cloud.py`` use for XML/dotted-key payloads.

**Caveat:** `MANIFEST` column paths were built from a live fetch of the SOFA
feed (2026-09-17), not a vendor schema reference — SOFA has no formal OpenAPI
spec at time of writing. Verify field names/nesting if the feed's shape
changes.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from posture.base import Collector, RateLimitedSignal

logger = logging.getLogger("posture.collectors.macadmins")

_FEED_URL = "https://sofafeed.macadmins.io/v1/macos_data_feed.json"

MANIFEST: dict[str, dict[str, Any]] = {
    "macos_releases": {
        "columns": {
            "os_version_name": ("os_version_name", "str"),
            "product_version": ("ProductVersion", "str"),
            "build": ("Build", "str"),
            "release_date": ("ReleaseDate", "datetime"),
            "release_type": ("ReleaseType", "str"),
            "security_info_url": ("SecurityInfo", "str"),
            "days_since_previous_release": ("DaysSincePreviousRelease", "int"),
            "unique_cves_count": ("UniqueCVEsCount", "int"),
            "exploited_cve_count": ("_exploited_cve_count", "int"),
        },
    },
    "macos_cves": {
        "derived_from": "macos_releases",
        "record_path": "_cves",
        "columns": {
            "product_version": ("$parent.ProductVersion", "str"),
            "cve_id": ("cve_id", "str"),
            "exploited": ("exploited", "bool"),
        },
    },
}


class MacadminsCollector(Collector):
    env_prefix = "MACADMINS"
    display_name = "MacAdmins SOFA Feed"
    manifest = MANIFEST
    # No credential exists to require — public, unauthenticated feed.
    config_keys: ClassVar[dict[str, bool]] = {}

    def _authenticate(self) -> None:
        # Public feed, nothing to authenticate — session needs no headers.
        pass

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource != "macos_releases":
            raise ValueError(f"Unknown resource '{resource}'")
        if cursor is not None:
            return [], None

        feed = self._fetch_feed()
        records: list[dict[str, Any]] = []
        for os_version in feed.get("OSVersions", []):
            os_version_name = os_version.get("OSVersion")
            latest = os_version.get("Latest") or {}
            latest_version = latest.get("ProductVersion")
            latest_build = latest.get("Build")
            for release in os_version.get("SecurityReleases", []):
                record = dict(release)
                record["os_version_name"] = os_version_name
                record["Build"] = (
                    latest_build
                    if release.get("ProductVersion") == latest_version
                    else None
                )
                cves: dict[str, bool] = release.get("CVEs") or {}
                record["_exploited_cve_count"] = sum(
                    1 for exploited in cves.values() if exploited is True
                )
                record["_cves"] = [
                    {"cve_id": cve_id, "exploited": exploited}
                    for cve_id, exploited in cves.items()
                ]
                records.append(record)
        return records, None

    def _fetch_feed(self) -> dict[str, Any]:
        response = self._session.get(_FEED_URL, timeout=30)
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitedSignal(
                retry_after=float(retry_after) if retry_after else None
            )
        response.raise_for_status()
        return response.json()
