# SecurityScorecard — credential setup

[← back to collector docs](../collectors/securityscorecard.md)

SecurityScorecard API tokens are account-scoped with no independent
read/write split — the token inherits whatever the generating account can
see. Generate it from a dedicated account rather than a personal admin's.

## Generate the API token

* Log in to the SecurityScorecard platform as the account the integration
  should run as.
* Navigate to **Settings** > **API Access** (or the account's API token
  page).
* Generate a new token and copy the value immediately — it is only shown
  once.

## Record the credentials

Store the following value securely — it maps directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| API Token | `token` | `SECURITYSCORECARD_TOKEN` |

**Caveat:** SecurityScorecard has no scoped/read-only token option — the
token is full-access to whatever the generating account can reach, so
least privilege here means choosing which account generates it, not a
permission you configure on the token itself.
