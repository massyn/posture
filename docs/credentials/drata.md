# Drata — credential setup

[← back to collector docs](../collectors/drata.md)

Drata API keys are account-scoped bearer tokens with no independent
read/write split — the key inherits whatever the generating account can
see. Generate it from a dedicated read-only-equivalent account rather than
a personal admin's.

## Generate the API key

* Log in to Drata as the account the integration should run as.
* Navigate to **Settings** > **Developers** (or the account's API settings
  page).
* Select **Generate API Key**, name it `CCM`, and copy the value
  immediately — it is only shown once.

## Record the credentials

Store the following value securely — it maps directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| API Key | `api_key` | `DRATA_API_KEY` |

`endpoint` (`DRATA_ENDPOINT`) is optional — only set it if Drata has given
your account a region-specific API host instead of the default.

**Caveat:** Drata has no scoped/read-only API key option — the key is
full-access to whatever the generating account can reach, so least
privilege here means choosing which account generates it, not a permission
you configure on the key itself.
