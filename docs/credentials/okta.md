# Okta — credential setup

[← back to collector docs](../collectors/okta.md)

Okta API tokens (`SSWS` tokens) inherit whatever admin role the creating
account holds — they are not independently scoped. These steps create a
dedicated service account with Okta's built-in **Read Only Administrator**
role, so the resulting token can't be used for anything beyond reads,
rather than reusing a personal admin's token.

## Create the service account

* Log in to the Okta Admin Console (`https://{yourOktaDomain}/admin`) as a
  Super Administrator.
* Navigate to **Directory** > **People** and create a new user for the
  integration (e.g. `ccm-readonly@yourdomain.com`), or use an existing
  dedicated service account if your org already provisions those centrally.

## Assign the Read Only Administrator role

* Navigate to **Security** > **Administrators** (or from the user's own
  profile, the **Admin roles** tab).
* Assign the **Read Only Administrator** role to the service account. This
  role can read users, groups, apps, and devices, but cannot make changes —
  the correct fit for this collector's `users`/`devices`/`device_users`
  resources.

## Generate the API token

* Sign in to Okta **as the service account** (tokens inherit the creating
  account's role, so the token must be created by this account, not an
  admin acting on its behalf).
* Navigate to **Security** > **API** > **Tokens**.
* Select **Create Token**, name it `CCM - Read Only`, and select **Create
  Token**.
* Copy the token value immediately — it is only shown once. Okta API tokens
  expire after 30 days of inactivity but auto-renew on each use, so a
  regularly-scheduled collection keeps it alive indefinitely.

## Record the credentials

Store the following values securely — these map directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| Okta domain (e.g. `yourorg.okta.com`) | `domain` | `OKTA_DOMAIN` |
| API Token | `token` | `OKTA_TOKEN` |
