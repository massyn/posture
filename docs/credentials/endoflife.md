# endoflife.date — credential setup

[← back to collector docs](../collectors/endoflife.md)

No credentials needed — endoflife.date's API is free and unauthenticated.
There is nothing to provision in a vendor console.

## Scoping collection

Two tables:

* `products` — every product endoflife.date tracks (478 at time of
  writing), one row each. Always unscoped.
* `cycles` — every release cycle, one row per release. With no products
  configured it pulls every product's cycles in a single request
  (`GET /products/full`). To limit it to particular products:
  * `products` (config key / `ENDOFLIFE_PRODUCTS`) sets a default product
    list for every `collect("cycles")` call, separated by commas and/or
    spaces, e.g. `ENDOFLIFE_PRODUCTS="python, ubuntu postgresql"`.
  * `ccm.collect("cycles", products=["python", "ubuntu", "postgresql"])`
    overrides that default for one call (kwargs win over the configured
    default, same rule every other collector's query-dialect kwargs follow).

Valid product ids are the `product` column of the `products` table.

## Record the credentials

| Value | Config key | Environment variable |
| --- | --- | --- |
| Default product list (optional) | `products` | `ENDOFLIFE_PRODUCTS` |
