# cve-db — credential setup

[← back to collector docs](../collectors/cve_db.md)

No credentials needed — [cve-db](https://cve-db.pages.dev) is a free,
unauthenticated static export of NVD CVE data. There is nothing to
provision in a vendor console.

## Optional: mirroring the export elsewhere

`base_url` (config key / `CVE_DB_BASE_URL`, default
`https://cve-db.pages.dev`) points the collector at a different host serving
the same `manifest.json` shape — useful only if you mirror the export
yourself.

## Record the credentials

| Value | Config key | Environment variable |
| --- | --- | --- |
| Base URL (optional) | `base_url` | `CVE_DB_BASE_URL` |
