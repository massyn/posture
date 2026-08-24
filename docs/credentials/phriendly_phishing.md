# PhriendlyPhishing — credential setup

[← back to collector docs](../collectors/phriendly_phishing.md)

These steps generate Reporting API credentials in the Phriendly Phishing
console. The Reporting API is inherently read-only (it has no write
endpoints), so there is no separate role/scope to restrict beyond
generating the credentials themselves. Note that Phriendly Phishing's
Reporting API data is only refreshed once per day (updated overnight), not
in real time.

## Generate the credentials

* Log in to your Phriendly Phishing platform as an administrator.
* Navigate to **Settings** > **Reporting API**.
* Generate the API credentials (client ID and client secret) from this
  page.
* Copy both values immediately — Phriendly Phishing does not store the
  secret for later display; if lost, use **Access Credentials** on the same
  page to have them re-sent, or regenerate.

**Caveat:** Phriendly Phishing's own admin console screens for this step
were not directly inspected — steps above are drawn from Phriendly
Phishing's public support documentation, not a live walkthrough. Confirm
the exact navigation against a real tenant before relying on this doc, and
correct it if the console has moved.

## Record the credentials

Store the following values securely — these map directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| Client ID | `client_id` | `PHRIENDLY_PHISHING_CLIENT_ID` |
| Client secret | `client_secret` | `PHRIENDLY_PHISHING_CLIENT_SECRET` |

Access tokens issued from these credentials expire after 12 hours; the
collector re-authenticates automatically, no action needed on your part.
