# DNSimple — credential setup

[← back to collector docs](../collectors/dnsimple.md)

These steps create an account-scoped API access token for the CCM
integration.

## Create the access token

* Log in to your DNSimple account.
* Navigate to your account page and select the **API & Access** tab.
* Under access tokens, select the option to add a new token.
* Choose an **Account** token (not a user token) — an account token is
  scoped to the resources of this account only, rather than every account
  the creating user belongs to.
* Label it `CCM - Read Only`, generate it, and copy the value immediately —
  it is only shown once.

**If your plan includes scoped access tokens** (DNSimple's Teams plan and
higher): restrict the token to read-only access on domains/zones rather
than issuing an unscoped account token — this feature is not available on
every plan, so it may not be an option depending on your subscription.

## Record the credentials

Store the following value securely — it maps directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| Access Token | `token` | `DNSIMPLE_TOKEN` |

`endpoint` (`DNSIMPLE_ENDPOINT`) is optional — only set it if you're
pointed at DNSimple's sandbox environment instead of production.

**Caveat:** whether your account has scoped (read-only) tokens available
depends on plan tier — confirm current availability against your own
DNSimple account before assuming a read-only token is possible; otherwise
the account token above is full-access by default and should be treated
accordingly.
