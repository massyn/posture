# HTTP headers — credential setup

[← back to collector docs](../collectors/http.md)

No credentials needed — this collector makes plain unauthenticated HTTP
requests. There is nothing to provision in a vendor console.

## Scoping collection

There is no credential to gate this collector, so the **list of hosts is the
scope boundary**. With no hosts configured, `ccm.collect("headers")` returns
zero rows and makes no network call at all. Tell it which hosts to probe
either via config/environment or per call:

* `hosts` (config key / `HTTP_HOSTS`, comma-separated) sets a default host
  list for every `collect("headers")` call.
* `ccm.collect("headers", hosts=["https://example.com", "http://example.com"])`
  overrides that default for one call (kwargs win over the configured
  default, same rule every other collector's query-dialect kwargs follow).

Each host must carry an explicit `http://` or `https://` scheme — it is not
defaulted, and a host without one raises. Scheme and port are part of the
host's identity: `https://host:8443` and `https://host` are two distinct
queries. Redirects are not followed; a 3xx response is captured as-is, with
its `Location` returned as an ordinary header row.

## Record the credentials

| Value | Config key | Environment variable |
| --- | --- | --- |
| Default host list (optional) | `hosts` | `HTTP_HOSTS` |
