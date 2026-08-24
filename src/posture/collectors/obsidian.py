"""Obsidian Security collector.

Raw ``requests`` against Obsidian's GraphQL API
(``https://api.obsec.io/v1/gql``), no vendor SDK. Auth is a static bearer
token issued out-of-band in the Obsidian console, same "just set the header"
shape as AppOmni/Snyk/UpGuard, just over GraphQL POST rather than REST GET.

Pagination is cursor-based, but with Obsidian's own field names rather than
the ``hasNextPage``/``endCursor`` Relay-style shape ``wiz.py`` uses:
``has_more_results`` (bool) / ``cursor`` (opaque string), read off the
top-level query result (``listGlobalPostureRules``/
``listGroupedPostureScoresPlatforms``) rather than nested under a
``pageInfo`` object.

``posture_rules`` is Obsidian's global posture-rule catalogue (SaaS
security-posture checks, one row per rule) via ``ListGlobalPostureRules``.
Each rule embeds a ``tenant_states`` list — the same rule's pass/fail result
per connected SaaS tenant — exploded into its own grain as
``posture_rule_tenant_states`` (``derived_from`` "posture_rules", the same
"nested list becomes its own resource with a ``$parent.`` FK" shape as
``crowdstrike.py``'s ``vulnerability_remediations``).

``posture_scores`` is the daily posture-score rollup via
``getScoreRankWidgetData``. One GraphQL call returns two independent
groupings in the same response — scores grouped by platform and scores
grouped by compliance standard — so both are exploded into one resource
distinguished by a ``group_by`` column rather than issuing the query twice
for the same data. Each grouping's score payload is itself a
``{key: {...metrics}}`` dict rather than a list of objects; ``_fetch_page``
reshapes it into one record per key (the same "flatten at fetch time, not in
parse.py" shape ``qualys.py``/``tenablesc.py`` use for their own
non-record-list envelopes) before parse.py ever sees it. Defaults to the
trailing day (``interval: DAILY``, matching the reference extraction script)
but ``filter``/``interval`` kwargs win over that default per the locked
kwargs-override-defaults rule.

Resources: ``posture_rules``, ``posture_rule_tenant_states``,
``posture_scores``.

**Caveat:** ``MANIFEST`` column paths and both GraphQL queries were ported
directly from a legacy in-house extraction script, not a live schema
introspection against a real tenant — no live credentials were available to
verify this collector. Same caveat tier as ``wiz.py``/``appomni.py``/etc.,
but stronger for pagination: the reference script advances the cursor using
only ``listGroupedPostureScoresPlatforms``'s ``has_more_results``/``cursor``
and ignores ``listGroupedPostureScoresCompliance``'s own pagination state
entirely — carried forward here unchanged rather than guessed at, but it
means a tenant with more compliance-grouped pages than platform-grouped ones
could truncate silently. Verify field names, the compliance-side pagination
assumption, and the score payload's actual metric keys against a real
tenant's response before relying on this collector.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar

from posture.base import Collector, RateLimitedSignal, UnauthorizedSignal

logger = logging.getLogger("posture.collectors.obsidian")

_DEFAULT_ENDPOINT = "https://api.obsec.io/v1/gql"
_RULES_PAGE_LIMIT = 25

_LIST_GLOBAL_POSTURE_RULES_QUERY = """
query ListGlobalPostureRules($limit: Limit, $cursor: ID, $filter: PostureRuleFilter, $order_by: [PostureRuleColumnOrder]) {
  listGlobalPostureRules(
    limit: $limit
    cursor: $cursor
    filter: $filter
    order_by: $order_by
  ) {
    has_more_results
    cursor
    rules {
      rule_id
      platform_id
      product_ids
      security_domain {
        id
        name
      }
      name
      risk_level
      standard_ids
      control_ids
      obsidian_rule
      release_label
      default_risk_level
      benchmark_value_type
      rule_value_type
      description
      remediation_instructions
      exceptions_count {
        active
        inactive
      }
      tenant_states {
        tenant_id
        is_passing
        violations
        tenant {
          tenantId
          name
          serviceId
          isProduction
          sensitivity {
            displayName
            enum
          }
          platform
        }
        last_scanned
        risk_accepted
        exceptions_count {
          active
          inactive
        }
        correction_score_change
      }
      total_violations
      correction_score_change
    }
    total
  }
}
"""

_GET_SCORE_RANK_WIDGET_DATA_QUERY = """
query getScoreRankWidgetData($filter: PostureScoreFilter, $interval: ListGroupedPostureScoresQueryInterval, $cursor: ID) {
  listGroupedPostureScoresPlatforms: listGroupedPostureScores(
    group_by: platforms
    filter: $filter
    interval: $interval
    cursor: $cursor
  ) {
    cursor
    has_more_results
    scores {
      start_datetime
      end_datetime
      scores
    }
  }
  listGroupedPostureScoresCompliance: listGroupedPostureScores(
    group_by: standards
    filter: $filter
    interval: $interval
    cursor: $cursor
  ) {
    cursor
    has_more_results
    scores {
      start_datetime
      end_datetime
      scores
    }
  }
}
"""

_DEFAULT_ORDER_BY = [
    {"column": "is_passing", "is_desc": False},
    {"column": "risk_level", "is_desc": True},
    {"column": "platform_id", "is_desc": False},
    {"column": "name", "is_desc": False},
]

MANIFEST: dict[str, dict[str, Any]] = {
    "posture_rules": {
        "endpoint": "listGlobalPostureRules",
        "columns": {
            "rule_id": ("rule_id", "str"),
            "platform_id": ("platform_id", "str"),
            "product_ids": ("product_ids", "json"),
            "security_domain_id": ("security_domain.id", "str"),
            "security_domain_name": ("security_domain.name", "str"),
            "name": ("name", "str"),
            "risk_level": ("risk_level", "str"),
            "default_risk_level": ("default_risk_level", "str"),
            "standard_ids": ("standard_ids", "json"),
            "control_ids": ("control_ids", "json"),
            "obsidian_rule": ("obsidian_rule", "bool"),
            "release_label": ("release_label", "str"),
            "benchmark_value_type": ("benchmark_value_type", "str"),
            "rule_value_type": ("rule_value_type", "str"),
            "description": ("description", "str"),
            "remediation_instructions": ("remediation_instructions", "str"),
            "exceptions_count_active": ("exceptions_count.active", "int"),
            "exceptions_count_inactive": ("exceptions_count.inactive", "int"),
            "total_violations": ("total_violations", "int"),
            "correction_score_change": ("correction_score_change", "float"),
        },
    },
    "posture_rule_tenant_states": {
        # tenant_states is a nested list per rule, not its own network call —
        # derived_from explodes it to its own grain, same shape as
        # crowdstrike.py's vulnerability_remediations.
        "derived_from": "posture_rules",
        "record_path": "tenant_states",
        "columns": {
            "rule_id": ("$parent.rule_id", "str"),
            "tenant_id": ("tenant_id", "str"),
            "is_passing": ("is_passing", "bool"),
            "violations": ("violations", "int"),
            "tenant_name": ("tenant.name", "str"),
            "tenant_service_id": ("tenant.serviceId", "str"),
            "tenant_is_production": ("tenant.isProduction", "bool"),
            "tenant_sensitivity": ("tenant.sensitivity.displayName", "str"),
            "tenant_platform": ("tenant.platform", "str"),
            "last_scanned": ("last_scanned", "datetime"),
            "risk_accepted": ("risk_accepted", "bool"),
            "exceptions_count_active": ("exceptions_count.active", "int"),
            "exceptions_count_inactive": ("exceptions_count.inactive", "int"),
            "correction_score_change": ("correction_score_change", "float"),
        },
    },
    "posture_scores": {
        # Reshaped at fetch time from a {key: {...metrics}} dict per grouping
        # into one flat record per key — see module docstring and
        # _flatten_score_groups.
        "endpoint": "listGroupedPostureScores",
        "columns": {
            "group_by": ("group_by", "str"),
            "key": ("key", "str"),
            "start_datetime": ("start_datetime", "datetime"),
            "end_datetime": ("end_datetime", "datetime"),
            "score_data": ("score_data", "json"),
        },
    },
}


class ObsidianCollector(Collector):
    env_prefix = "OBSIDIAN"
    display_name = "Obsidian Security"
    manifest = MANIFEST
    config_keys: ClassVar[dict[str, bool]] = {"token": True, "endpoint": False}
    url_config_keys: tuple[str, ...] = ()  # endpoint is a full GraphQL path, not a host

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        self._endpoint = self._config.get("endpoint", _DEFAULT_ENDPOINT)

    def _authenticate(self) -> None:
        self._session.headers["Authorization"] = f"Bearer {self._config['token']}"
        self._session.headers["Content-Type"] = "application/json"
        self._session.headers["Accept"] = "application/json"

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "posture_rules":
            return self._fetch_posture_rules_page(kwargs, cursor)
        if resource == "posture_scores":
            return self._fetch_posture_scores_page(kwargs, cursor)
        raise ValueError(f"Unsupported resource '{resource}'")

    def _fetch_posture_rules_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        variables: dict[str, Any] = {
            "limit": _RULES_PAGE_LIMIT,
            "cursor": cursor,
            "filter": {"AND": []},
            "order_by": _DEFAULT_ORDER_BY,
        }
        variables.update(kwargs)
        body = self._post(_LIST_GLOBAL_POSTURE_RULES_QUERY, variables, "posture_rules")

        result = body["data"]["listGlobalPostureRules"]
        next_cursor = result["cursor"] if result.get("has_more_results") else None
        return result.get("rules", []) or [], next_cursor

    def _fetch_posture_scores_page(
        self, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime(
            "%Y-%m-%d"
        )
        variables: dict[str, Any] = {
            "filter": {"AND": [{"datetime": {"GTE": f"{yesterday}T00:00:00.000Z"}}]},
            "interval": "DAILY",
            "cursor": cursor,
        }
        variables.update(kwargs)
        body = self._post(
            _GET_SCORE_RANK_WIDGET_DATA_QUERY, variables, "posture_scores"
        )
        data = body["data"]

        records = _flatten_score_groups(
            "platforms", data["listGroupedPostureScoresPlatforms"]["scores"]
        ) + _flatten_score_groups(
            "standards", data["listGroupedPostureScoresCompliance"]["scores"]
        )

        # Pagination is driven off the platforms grouping only, matching the
        # reference extraction script — see the module docstring's caveat.
        platforms_result = data["listGroupedPostureScoresPlatforms"]
        next_cursor = (
            platforms_result["cursor"]
            if platforms_result.get("has_more_results")
            else None
        )
        return records, next_cursor

    def _post(
        self, query: str, variables: dict[str, Any], resource: str
    ) -> dict[str, Any]:
        response = self._session.post(
            self._endpoint,
            json={"query": query, "variables": variables},
            timeout=30,
        )
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitedSignal(
                retry_after=float(retry_after) if retry_after else None
            )
        if response.status_code in (401, 403):
            raise UnauthorizedSignal()
        response.raise_for_status()
        body = response.json()
        if body.get("errors"):
            raise RuntimeError(
                f"Obsidian GraphQL errors for '{resource}': {body['errors']}"
            )
        return body


def _flatten_score_groups(
    group_by: str, score_periods: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Reshape ``[{start_datetime, end_datetime, scores: {key: {...}}}]``
    into one flat record per (period, key)."""
    records: list[dict[str, Any]] = []
    for period in score_periods:
        scores = period.get("scores") or {}
        for key, score_data in scores.items():
            records.append(
                {
                    "group_by": group_by,
                    "key": key,
                    "start_datetime": period.get("start_datetime"),
                    "end_datetime": period.get("end_datetime"),
                    "score_data": score_data,
                }
            )
    return records
