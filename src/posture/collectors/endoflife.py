"""endoflife.date collector.

Raw ``requests`` against endoflife.date's v1 API (``https://endoflife.date/api/v1``),
no vendor SDK — public data, no auth of any kind. That's the one thing that
makes this collector unlike every other one in this codebase: there is no
credential to gate it, so ``config_keys`` has no required keys and
``runnable_sources()`` always reports it ready. Rather than inventing a fake
required credential (which would break the "explicit collect() call" contract
every other source honours), the collector makes an unscoped call genuinely
free: ``products`` (config key / ``ENDOFLIFE_PRODUCTS``, comma-separated, or
the ``products`` kwarg, a comma-separated string or a list — kwarg wins per
the locked kwargs-override rule) defaults to empty, and an empty resolved
product list short-circuits ``_fetch_page`` before any HTTP request is
made. A generic loop over every
registered source's resources (e.g. ``scripts/extract_test.py``) therefore
makes zero network calls against this source unless an operator has
deliberately named products to track, either via env var or kwarg.

One resource, ``cycles``: one ``GET /products/<id>`` call per configured
product id (paginated one product per page — not batched — so a failure on
product N doesn't discard N-1 already-yielded pages, no per-item thread-pool
fan-out needed given the small product counts this is used for). Each
release in the response's nested ``releases`` list becomes one row, with the
requesting product's id/label injected onto it (not present in the release
object itself).

**Schema note — allowlist, not normalisation.** endoflife.date's v1 API is
mostly consistent across products (the classic v0-API ambiguity, where `eol`
was either a bool or a date string in the same field, is gone — v1 cleanly
splits every lifecycle flag into an `isX` bool + a separate `xFrom` date-or-
null), but which optional lifecycle fields a product's releases carry at all
varies: `isEoas`/`eoasFrom` (end of active support) and `isEoes`/`eoesFrom`
(end of extended support) are present for some products (ubuntu, debian) and
entirely absent for others (chrome, postgresql) — not null-valued, the keys
just don't exist. `MANIFEST` declares the union of columns the API can
produce; `parse.py`'s dotted-path lookup already treats a missing key the
same as an explicit null, so a product with no EOAS/EOES concept just yields
`NaN`/`NaT` in those columns, the same as any other unset field on any other
collector. This is not reinterpreting endoflife.date's own field semantics —
same raw-field-names-and-meaning allowlist convention as every other
collector, just declared over a superset schema. `custom` (an arbitrary,
per-product dict — e.g. python's `{"pep": "PEP-0745"}`) has no fixed key set
across products, so it's typed `json` rather than exploded into columns.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from posture.base import Collector, RateLimitedSignal

logger = logging.getLogger("posture.collectors.endoflife")

_BASE_URL = "https://endoflife.date/api/v1"

MANIFEST: dict[str, dict[str, Any]] = {
    "cycles": {
        "columns": {
            "product": ("product", "str"),
            "product_label": ("product_label", "str"),
            "cycle": ("name", "str"),
            "label": ("label", "str"),
            "codename": ("codename", "str"),
            "release_date": ("releaseDate", "datetime"),
            "is_lts": ("isLts", "bool"),
            "lts_from": ("ltsFrom", "datetime"),
            "is_eoas": ("isEoas", "bool"),
            "eoas_from": ("eoasFrom", "datetime"),
            "is_eol": ("isEol", "bool"),
            "eol_from": ("eolFrom", "datetime"),
            "is_eoes": ("isEoes", "bool"),
            "eoes_from": ("eoesFrom", "datetime"),
            "is_maintained": ("isMaintained", "bool"),
            "latest_version": ("latest.name", "str"),
            "latest_date": ("latest.date", "datetime"),
            "latest_link": ("latest.link", "str"),
            "custom": ("custom", "json"),
        }
    }
}


class EndoflifeCollector(Collector):
    env_prefix = "ENDOFLIFE"
    display_name = "endoflife.date"
    manifest = MANIFEST
    # No credential exists to require — declared anyway (as not-required) so
    # catalog()/generated docs document the products default the same way
    # every other collector's optional config is documented.
    config_keys: ClassVar[dict[str, bool]] = {"products": False}

    def __init__(
        self, config: dict[str, Any] | None = None, *, record_limit: int | None = None
    ) -> None:
        super().__init__(config, record_limit=record_limit)
        self._default_products = _split_products(self._config.get("products"))

    def _authenticate(self) -> None:
        # Public API, nothing to authenticate — session needs no headers.
        pass

    def _resolve_products(self, kwargs: dict[str, Any]) -> list[str]:
        products = kwargs.get("products")
        if products is None:
            return self._default_products
        if isinstance(products, str):
            return _split_products(products)
        return list(products)

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource != "cycles":
            raise ValueError(f"Unknown resource '{resource}'")

        products = self._resolve_products(kwargs)
        if not products:
            return [], None

        index = cursor or 0
        product_id = products[index]
        records = self._fetch_product_cycles(product_id)
        next_cursor = index + 1 if index + 1 < len(products) else None
        return records, next_cursor

    def _fetch_product_cycles(self, product_id: str) -> list[dict[str, Any]]:
        response = self._session.get(f"{_BASE_URL}/products/{product_id}", timeout=30)
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitedSignal(
                retry_after=float(retry_after) if retry_after else None
            )
        if response.status_code == 404:
            raise ValueError(
                f"Unknown endoflife.date product '{product_id}' — check the id "
                f"against GET {_BASE_URL}/products"
            )
        response.raise_for_status()

        result = response.json()["result"]
        releases: list[dict[str, Any]] = result.get("releases", [])
        records: list[dict[str, Any]] = []
        for release in releases:
            record = dict(release)
            record["product"] = result.get("name", product_id)
            record["product_label"] = result.get("label")
            records.append(record)
        return records


def _split_products(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return list(value)
