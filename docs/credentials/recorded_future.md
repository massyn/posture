# Recorded Future — credential setup

[← back to collector docs](../collectors/recorded_future.md)

Recorded Future API tokens are generated per-user and inherit that user's
own module entitlements — they are not independently scoped. Generate the
token from a dedicated integration user with only the modules this
collector needs (Alerts, Vulnerability Intelligence) enabled, rather than a
personal analyst or admin account.

## Generate the API token

* You must be an Enterprise Administrator, or have an Enterprise
  Administrator generate this on your behalf.
* Log in to the Recorded Future portal as the account the token should be
  scoped to.
* Navigate to the account/API settings page and create a new API token.
* Copy the token value immediately — it is only shown once.

## Record the credentials

Store the following value securely — it maps directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| API Token | `token` | `RECORDEDFUTURE_TOKEN` |

**Caveat:** Recorded Future has no read-only token flag — the token carries
whatever module/API entitlements the generating account has. Least privilege
here means provisioning a dedicated integration user with only the Alerts
and Vulnerability Intelligence modules licensed, not a token permission
configured at generation time.
