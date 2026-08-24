# Precise — credential setup

[← back to collector docs](../collectors/precise.md)

Precise (precise.io) has no public API documentation we could find, so
unlike the other `docs/credentials/*.md` pages, this one can't walk through
console navigation steps to provision the token — only the two values the
collector actually needs and where they came from.

## What's needed

* **API token** — a bearer token for `Authorization: Bearer <token>`.
  Obtain it from whoever administers your organization's Precise instance;
  it was previously issued directly rather than self-served through a
  documented console flow.
* **Instance** — the tenant identifier embedded in Precise's API URL
  (`https://api.precise.io/v1/<instance>/profiles`) — e.g. `mantelgroup`.
  This is your organization's Precise instance name, not a secret.

## Record the credentials

Store the following values securely — these map directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| API token | `token` | `PRECISE_TOKEN` |
| Instance identifier | `instance` | `PRECISE_INSTANCE` |
