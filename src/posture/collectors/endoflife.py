"""endoflife.date collector.

Raw ``requests`` against endoflife.date's v1 API (``https://endoflife.date/api/v1``),
no vendor SDK — public data, no auth of any kind. That's the one thing that
makes this collector unlike every other one in this codebase: there is no
credential to gate it, so ``config_keys`` has no required keys and
``runnable_sources()`` always reports it ready. It is still never picked up
by ``catalog(filter="environment")`` (nothing to check), so a default
``posturecollect`` run only reaches it via ``--include``.

Two resources:

* ``products`` — ``GET /products``, every product endoflife.date tracks
  (one row each, one request, unscoped).
* ``cycles`` — every release cycle, one row per release with the owning
  product's id/label injected onto it (not present in the release object
  itself). Scoped by ``products`` (config key / ``ENDOFLIFE_PRODUCTS``, or the
  ``products`` kwarg — a string or a list, kwarg wins per the locked
  kwargs-override rule); a string is split on commas and/or whitespace.
  With no products resolved, every product's cycles are fetched in a single
  ``GET /products/full`` call (one page) rather than one request per
  product. With products named, it's one ``GET /products/<id>`` per product,
  one product per page — so a failure on product N doesn't discard N-1
  already-yielded pages.

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
import re
from typing import Any, ClassVar

from posture.base import Collector, RateLimitedSignal

logger = logging.getLogger("posture.collectors.endoflife")

_BASE_URL = "https://endoflife.date/api/v1"

MANIFEST: dict[str, dict[str, Any]] = {
    "products": {
        "columns": {
            "product": ("name", "str"),
            "label": ("label", "str"),
            "category": ("category", "str"),
            "aliases": ("aliases", "json"),
            "tags": ("tags", "json"),
            "uri": ("uri", "str"),
        }
    },
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
    },
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
        return _split_products(products)

    def _fetch_page(
        self, resource: str, kwargs: dict[str, Any], cursor: Any
    ) -> tuple[list[dict[str, Any]], Any]:
        if resource == "products":
            return self._get("/products"), None
        if resource != "cycles":
            raise ValueError(f"Unknown resource '{resource}'")

        products = self._resolve_products(kwargs)
        if not products:
            records = [
                record
                for product in self._get("/products/full")
                for record in _release_records(product)
            ]
            return records, None

        index = cursor or 0
        product_id = products[index]
        records = _release_records(self._get(f"/products/{product_id}"))
        next_cursor = index + 1 if index + 1 < len(products) else None
        return records, next_cursor

    def _get(self, path: str) -> Any:
        response = self._session.get(f"{_BASE_URL}{path}", timeout=60)
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitedSignal(
                retry_after=float(retry_after) if retry_after else None
            )
        if response.status_code == 404:
            raise ValueError(
                f"endoflife.date returned 404 for {path} — check product ids "
                f"against GET {_BASE_URL}/products"
            )
        response.raise_for_status()
        return response.json()["result"]


def _release_records(product: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {**release, "product": product["name"], "product_label": product.get("label")}
        for release in product.get("releases", [])
    ]


def _split_products(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [item for item in re.split(r"[,\s]+", value) if item]
    return list(value)
