# Healthchecks.io — credential setup

[← back to collector docs](../collectors/healthchecks.md)

Healthchecks.io has no OAuth flow and no service-account concept. API
access is a per-**project** key sent in the `X-Api-Key` header. Each
project can have two keys:

| Key | Prefix | Access |
| --- | --- | --- |
| API key | *(none)* | Full read **and write** — create/update/pause/delete checks, list integrations, read ping bodies |
| Read-only API key | `hcr_` | List checks and read their status-change history (flips) only |

Use the **read-only API key** for posture. It covers both resources this
collector reads (`checks`, `flips`) and cannot modify anything if it
leaks. The trade-offs, all acceptable for posture:

* Check objects come back with a `unique_key` field instead of the real
  `uuid`, and omit `ping_url` / `update_url` / `channels`.
* The `channels` (integrations) and per-ping endpoints are not accessible
  — posture does not collect them.

## Create the read-only API key

1. Sign in to Healthchecks.io and select the project whose checks posture
   should collect (the key is scoped to a single project — repeat these
   steps per project, each becoming its own posture instance).
2. Open the project's **Settings** page (gear icon / project name →
   **Settings**).
3. Find the **API Access** section.
4. If **API Access** is set to **Off**, switch it to **On**. To keep
   write access disabled entirely, choose **Read-only** — the collector
   only needs the read-only key regardless of this setting.
5. Click **Create** next to **API key (read-only)** (or **Show** if one
   already exists) and copy the value. It starts with `hcr_`.
6. Leave the full **API key** unset / unshared — posture does not need it.

To revoke access later, return to the same screen and click **Revoke** on
the read-only key; the full API key (if any) is unaffected.

## Self-hosted instances

For a self-hosted Healthchecks instance, set `api_url` (config key) /
`HEALTHCHECKS_API_URL` (env var) to the instance's base URL, e.g.
`https://healthchecks.example.com`. It defaults to
`https://healthchecks.io`. The key is created the same way in that
instance's own project settings.

## Record the credentials

| Value | Config key | Environment variable |
| --- | --- | --- |
| Read-only API key | `token` | `HEALTHCHECKS_TOKEN` |
| Base URL (self-hosted only) | `api_url` | `HEALTHCHECKS_API_URL` |
