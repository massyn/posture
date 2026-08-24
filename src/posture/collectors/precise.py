"""Precise (precise.io) collector.

Raw ``requests`` against Precise's REST API — no vendor SDK, static bearer
token auth. Reference implementation:
``https://github.com/Shuffle/python-apps`` (see the Precise plugin's
``Source.profiles()`` — page-based pagination via a plain ``?page=N`` query
param, terminating when a page 404s or returns an empty list, confirmed
live against a real tenant).

The reference hardcodes the tenant instance ("mantelgroup") directly into
the endpoint URL. posture never hardcodes a tenant identifier into a
collector — it's config, resolved the same way as every other collector's
config keys — so ``instance`` (env var ``PRECISE_INSTANCE``) is substituted
into the URL template instead; the URL's shape
(``https://api.precise.io/v1/{instance}/profiles``) is otherwise unchanged
from the reference.

``profiles`` carries only scalar/``about`` fields — every list-shaped field
on the raw profile record (``network``, ``education``, ``experience``,
``skills``, ``certifications``, ``conferences``, ``tracks``) is exploded
into its own ``derived_from="profiles"`` resource instead of kept as a
``json`` blob column, the same ``record_path``/``$parent`` shape as
``crowdstrike.py``'s ``vulnerability_remediations`` — each derived row
carries the parent profile's id/owner email back via ``$parent``, so every
resource here is queryable with plain SQL (a join on ``profile_id``, no
JSON-extraction functions) once loaded into a backend. Per that same
crowdstrike.py precedent, a field fully covered by a derived resource is
dropped from ``profiles`` itself rather than duplicated in both places.

**One level of nesting stays as JSON, disclosed rather than silently
dropped:** each ``experience`` entry carries its own nested ``projects``
list (a person's project engagements within that role) and an ``industry``
list (numeric-ish category ids). posture's ``derived_from``/``record_path``
mechanism only explodes one list level per resource — the source it reads
is the raw ``profiles`` record, not another *derived* resource's already-
exploded rows, so a ``profile_projects`` table derived from
``profile_experience`` isn't achievable without a parse.py change (multi-
level ``record_path``, e.g. ``"experience.*.projects"``). Flag if that's
wanted; for now ``profile_experience.projects``/``.industry`` stay as
``json`` columns, and ``profile_projects.industry`` likewise.

Resources: ``profiles``, ``profile_network``, ``profile_education``,
``profile_experience``, ``profile_skills``, ``profile_certifications``,
``profile_conferences``, ``profile_tracks``.

**Caveat:** every field name here (including every derived resource's
nested-item keys) was observed from one real tenant's ~590 records across
its full pull, not from a published API reference (Precise has none we
could find). Comprehensive for that tenant at pull time; a field that
simply never appeared could still exist. Verify against a fresh pull
before treating this manifest as exhaustive for a different tenant.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger = logging.getLogger("posture.collectors.precise")

_BASE_URL = "https://api.precise.io/v1"
_PROFILES_PATH = "/{instance}/profiles"

MANIFEST: dict[str, dict[str, Any]] = {
    "profiles": {
        "endpoint": _PROFILES_PATH,
        "columns": {
            "profile_id": ("id", "str"),
            "owner_email": ("owner", "str"),
            "path": ("path", "str"),
            "about_name": ("about.name", "str"),
            "about_title": ("about.title", "str"),
            "about_bio": ("about.bio", "str"),
            "about_passion": ("about.passion", "str"),
            "about_photo_url": ("about.photo_url", "str"),
            "about_pronounce_name_url": ("about.pronounce_name_url", "str"),
            "preference": ("preference", "str"),
            "completeness_score": ("completeness_score", "int"),
            "membership_id": ("membership_id", "int"),
            "created_at": ("created_at", "datetime"),
            "updated_at": ("updated_at", "datetime"),
        },
    },
    "profile_network": {
        "derived_from": "profiles",
        "record_path": "network",
        "columns": {
            "profile_id": ("$parent.id", "str"),
            "owner_email": ("$parent.owner", "str"),
            "type": ("type", "str"),
            "url": ("url", "str"),
        },
    },
    "profile_education": {
        "derived_from": "profiles",
        "record_path": "education",
        "columns": {
            "profile_id": ("$parent.id", "str"),
            "owner_email": ("$parent.owner", "str"),
            "place": ("place", "str"),
            "period": ("period", "str"),
            "description": ("description", "str"),
        },
    },
    "profile_experience": {
        "derived_from": "profiles",
        "record_path": "experience",
        "columns": {
            "profile_id": ("$parent.id", "str"),
            "owner_email": ("$parent.owner", "str"),
            "catalog_id": ("catalog_id", "int"),
            "place": ("place", "str"),
            "period": ("period", "str"),
            "role": ("role", "str"),
            "description": ("description", "str"),
            # One level deeper than record_path can reach in a single
            # resource — see module docstring's "one level of nesting"
            # note.
            "industry": ("industry", "json"),
            "projects": ("projects", "json"),
        },
    },
    "profile_skills": {
        "derived_from": "profiles",
        "record_path": "skills",
        "columns": {
            "profile_id": ("$parent.id", "str"),
            "owner_email": ("$parent.owner", "str"),
            "name": ("name", "str"),
            "level": ("level", "int"),
            "org_skill_id": ("org_skill_id", "int"),
            "preference": ("preference", "int"),
        },
    },
    "profile_certifications": {
        "derived_from": "profiles",
        "record_path": "certifications",
        "columns": {
            "profile_id": ("$parent.id", "str"),
            "owner_email": ("$parent.owner", "str"),
            "name": ("name", "str"),
            "org_certification_id": ("org_certification_id", "str"),
            "place": ("place", "str"),
            "period": ("period", "str"),
            # Day-first (DD/MM/YYYY), confirmed against the unambiguous
            # day-month-name dates in "period" — an explicit format hint,
            # not left to the generic parser: pandas' default assumes
            # month-first, which would silently flip an ambiguous date
            # (e.g. "01/07/2028", 1 July) to the wrong day (7 January).
            "valid_from": ("valid_from", "datetime", {"format": "%d/%m/%Y"}),
            "valid_to": ("valid_to", "datetime", {"format": "%d/%m/%Y"}),
        },
    },
    "profile_conferences": {
        "derived_from": "profiles",
        "record_path": "conferences",
        "columns": {
            "profile_id": ("$parent.id", "str"),
            "owner_email": ("$parent.owner", "str"),
            "place": ("place", "str"),
            "title": ("title", "str"),
        },
    },
    "profile_tracks": {
        "derived_from": "profiles",
        "record_path": "tracks",
        "columns": {
            "profile_id": ("$parent.id", "str"),
            "owner_email": ("$parent.owner", "str"),
            "category": ("category", "str"),
            "name": ("name", "str"),
            "level": ("level", "int"),
            "desc": ("desc", "str"),
            "visible": ("visible", "bool"),
        },
    },
}


class PreciseCollector(Collector):
    env_prefix = "PRECISE"
    display_name = "Precise"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {"token": True, "instance": True}

    def _authenticate(self) -> None:
        self._session.headers["Authorization"] = f"Bearer {self._config['token']}"
        self._session.headers["Accept"] = "application/json"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource != "profiles":
            raise ValueError(f"Unsupported resource '{resource}'")

        page = cursor if cursor is not None else 1
        url = _BASE_URL + _PROFILES_PATH.format(instance=self._config["instance"])
        params: dict[str, Any] = {"page": page}
        params.update(kwargs)

        response = self._get(url, params)
        if response is None:
            return [], None  # 404: no more pages, per the reference implementation

        records = response.json()
        if not isinstance(records, list) or not records:
            return [], None
        return records, page + 1

    def _get(self, url: str, params: dict[str, Any]) -> Any:
        response = self._session.get(url, params=params, timeout=30)
        if response.status_code == 404:
            return None
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitedSignal(
                retry_after=float(retry_after) if retry_after else None
            )
        if response.status_code == 401:
            raise UnauthorizedSignal()
        if response.status_code != 200:
            logger.warning(
                "unexpected status code",
                extra={"source": "precise", "status_code": response.status_code},
            )
        response.raise_for_status()
        return response
