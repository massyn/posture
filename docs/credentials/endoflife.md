# endoflife.date — credential setup

[← back to collector docs](../collectors/endoflife.md)

No credentials needed — endoflife.date's API is free and unauthenticated.
There is nothing to provision in a vendor console.

## Scoping collection

Because there's no credential to gate this collector, `ccm.collect("cycles")`
with no products configured returns zero rows and makes no network call at
all — it does not default to pulling every product endoflife.date tracks
(400+ at time of writing). Tell it which products to track either via
config/environment or per call:

* `products` (config key / `ENDOFLIFE_PRODUCTS`, comma-separated) sets a
  default product list for every `collect("cycles")` call.
* `ccm.collect("cycles", products=["python", "ubuntu", "postgresql"])`
  overrides that default for one call (kwargs win over the configured
  default, same rule every other collector's query-dialect kwargs follow).

Find valid product ids via `GET https://endoflife.date/api/v1/products`.

## Record the credentials

| Value | Config key | Environment variable |
| --- | --- | --- |
| Default product list (optional) | `products` | `ENDOFLIFE_PRODUCTS` |
